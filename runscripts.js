//Not currently using this file anymore, will probably delete.

const { execSync } = require('child_process');

function runScriptSync(scriptName) {
    try {
        console.log(`Running ${scriptName}...`);
        const output = execSync(`node ${scriptName}`, { stdio: 'inherit' });
        console.log(`Finished running ${scriptName}`);
    } catch (error) {
        console.error(`Error executing ${scriptName}:`, error.message);
    }
}
// Run scripts in sequence
runScriptSync('createtables.js');
console.log('All scripts have been executed.');
