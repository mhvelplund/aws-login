const { prompt: eprompt, Select } = require("enquirer");
const package_json = require("../package.json");
const request = promisify(require("request"));
const xpath = require("xpath");
import { DOMParser } from "xmldom";
import { parse, HTMLElement } from "node-html-parser";
import { promisify } from "util";
import { STS } from "aws-sdk";
import program, { CommanderStatic } from "commander";


async function assumeRoleWithSAML(program: { tokenDuration: number, profile: string }, role: string, assertion: string) {
	const [PrincipalArn, RoleArn] = role.split(",");
	const sts = new STS();

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
		} = Credentials as STS.Credentials;
		const Arn = (AssumedRoleUser as STS.AssumedRoleUser).Arn;

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
		name: "server",
		message: `ADFS server (Example: "sts.example.org")`
	});
}
if (!program.username) {
	prompts.push({
		type: "input",
		name: "user",
		message: `Username (Example: "jdoe@example.org")`
	});
}
if (!program.password) {
	prompts.push({
		type: "password",
		name: "pass",
		message: "Password"
	});
}

(async () => {
	const { user, pass, server } = await eprompt(prompts);

	const username: string = program.username || user;
	const password: string = program.password || pass;
	const adfsServer: string = program.adfsServer || server;

	const inputPar = {
		UserName: username,
		Password: password,
		AuthMethod: "FormsAuthentication"
	};

	try {
		const res = await request({
			method: "POST",
			followAllRedirects: true,
			form: inputPar,
			url: `https://${adfsServer}/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices`,
			jar: true
		})

		const inputs = (parse(res.body) as HTMLElement)
			.querySelectorAll("input")
			.filter(tag => tag && tag.attributes && "SAMLResponse" == tag.attributes.name);

		if (!inputs || inputs.length == 0) {
			console.error("ERROR:", "Login failed");
			process.exit(1);
		}

		const assertion: string = inputs[0].attributes.value; // Base64 encoded assertion
		const xml = Buffer.from(assertion, "base64").toString("ascii");
		const doc = new DOMParser().parseFromString(xml);
		const select = xpath.useNamespaces({ saml: "urn:oasis:names:tc:SAML:2.0:assertion" });
		const nodes = select(
			"//saml:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml:AttributeValue/text()",
			doc
		);

		const roles = nodes
			.map((e: { data: string }) => e.data)
			.filter((e: string) => !program.filter || e.includes(program.filter));

		if (roles.length == 0) {
			if (program.filter) {
				console.error("ERROR:", `No roles matching filter "${program.filter}"`);
				process.exit(1);
			}
		}

		// Hack :)
		const p = <{ tokenDuration: number, profile: string }><unknown>program;

		if (roles.length == 1) {
			await assumeRoleWithSAML(p, roles[0], assertion);
		} else {
			const prompt = new Select({
				name: "role",
				message: "Assume role",
				choices: roles
			});

			const role = await prompt.run();
			await assumeRoleWithSAML(p, role, assertion);
		}
	} catch (error) {
		console.error("ERROR:", error.message);
		process.exit(1);
	}
})()
