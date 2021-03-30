#!/usr/bin/env node
// Thanks, SO: https://stackoverflow.com/a/25299690/511976
var fs = require('fs');
var path = process.argv[2];
var data = "#!/usr/bin/env node\n\n";
data += fs.readFileSync(path);
fs.writeFileSync(path, data);
