#!/usr/bin/env node

const program = require("commander");
const package_json = require("./package.json");
const parse = require("node-html-parser").parse;
const xpath = require("xpath");
const dom = require("xmldom").DOMParser;
const AWS = require("aws-sdk");
const promisify = require("util").promisify;
const request = promisify(require("request"));
const { prompt, Select } = require("enquirer");

async function assumeRoleWithSAML(program, role, assertion) {
	const [PrincipalArn, RoleArn] = role.split(",");
	const sts = new AWS.STS();

	try {
		let data = await sts.assumeRoleWithSAML(
			{
				DurationSeconds: program.tokenDuration,
				PrincipalArn,
				RoleArn,
				SAMLAssertion: assertion
			}).promise();
		const { Credentials, AssumedRoleUser } = data;
		const {
			AccessKeyId,
			SecretAccessKey,
			SessionToken,
			Expiration
		} = Credentials;
		const Arn = AssumedRoleUser.Arn;

		console.log(`Assumed "${Arn}" as "${program.profile}" until "${Expiration}"`);

		const credentialFile = `${require("os").homedir()}/.aws/credentials`;
		const ConfigParser = require("configparser");
		const config = new ConfigParser();
		config.read(credentialFile);
		if (!config.hasSection(program.profile)) {
			config.addSection(program.profile);
		}
		config.set(program.profile, "aws_access_key_id", AccessKeyId);
		config.set(
			program.profile,
			"aws_secret_access_key",
			SecretAccessKey
		);
		config.set(program.profile, "aws_session_token", SessionToken);
		config.write(credentialFile);
	} catch (error) {
		console.error("ERROR", error.message);
		process.exit(1);
	}
}

program.version(package_json.version).description(package_json.description);

program
	.option(
		"-s, --adfs-server <adfs-server>",
		`the username to user. Example: "sts.example.org"`
	)
	.option(
		"-u, --username <username>",
		`the username to user. Example: "jdoe@example.org"`
	)
	.option("--password <password>", "the password for the user")
	.option(
		"-f, --filter <filter>",
		"filter for returned role values. Specify full name (or unique match) to avoid selecting role and login directly."
	)
	.option(
		"-t, --token-duration <token-duration>",
		"token duration in seconds. Default is 3600 which is the default in AWS, but generally speaking longer durations are more convenient.",
		3600
	)
	.option(
		"-p, --profile <profile>",
		"specify which profile name to store settings in.",
		"default"
	);

program.parse(process.argv);

const prompts = [];

if (!program.adfsServer) {
	prompts.push({
		type: "input",
		name: "f",
		message: `ADFS server (Example: "sts.example.org")`
	});
}
if (!program.username) {
	prompts.push({
		type: "input",
		name: "u",
		message: `Username (Example: "jdoe@example.org")`
	});
}
if (!program.password) {
	prompts.push({
		type: "password",
		name: "p",
		message: "Password"
	});
}

let username, password, adfsServer;
prompt(prompts).then(answers => {
	let { u, p, f } = answers;
	username = program.username || u;
	password = program.password || p;
	adfsServer = program.adfsServer || f;

	const inputPar = {
		UserName: username,
		Password: password,
		AuthMethod: "FormsAuthentication"
	};

	let assertion;

	request({
		method: "POST",
		followAllRedirects: true,
		form: inputPar,
		url: `https://${adfsServer}/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices`,
		jar: true
	})
		.catch(error => {
			console.error("ERROR:", error.message);
			process.exit(1);
		})
		.then(res => {
			const inputs = parse(res.body)
				.querySelectorAll("input")
				.filter(
					tag =>
						tag && tag.attributes && "SAMLResponse" == tag.attributes.name
				);

			if (!inputs || inputs.length == 0) {
				console.error("ERROR:", "Login failed");
				process.exit(1);
			}

			assertion = inputs[0].attributes.value; // Base64 encoded assertion
			const xml = new Buffer.from(assertion, "base64").toString("ascii");
			const doc = new dom().parseFromString(xml);
			const select = xpath.useNamespaces({
				saml: "urn:oasis:names:tc:SAML:2.0:assertion"
			});
			const nodes = select(
				"//saml:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml:AttributeValue/text()",
				doc
			);

			const roles = nodes
				.map(e => e.data)
				.filter(e => !program.filter || e.includes(program.filter));

			if (roles.length == 0) {
				if (program.filter) {
					console.error(
						"ERROR:",
						`No roles matching filter "${program.filter}"`
					);
					process.exit(1);
				}
			}

			const assumeRole = promisify(assumeRoleWithSAML);

			if (roles.length == 1) {
				assumeRole(program, roles[0], assertion);
			} else {
				const prompt = new Select({
					name: "role",
					message: "Assume role",
					choices: roles
				});

				prompt
					.run()
					.then(answer => {
						assumeRole(program, answer, assertion);
					})
					.catch(error => {
						console.error("ERROR:", error.message);
						process.exit(1);
					});
			}
		});
});
