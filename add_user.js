const sqlite3 = require('sqlite3').verbose();
const readline = require('readline');

// Create an interface to prompt the user for input
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// Connect to the SQLite database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
});

// Function to prompt the user and insert data into the database
function addUser() {
    rl.question('Enter your name: ', (name) => {
        rl.question('Enter your email: ', (email) => {

            // Insert the data into the users table
            db.run(`INSERT INTO users (name, email) VALUES (?, ?)`, [name, email], function(err) {
                if (err) {
                    console.error(err.message);
                } else {
                    console.log(`User added with rowid ${this.lastID}`);
                }

                // Close the database and readline interface after operation
                db.close((err) => {
                    if (err) {
                        console.error(err.message);
                    }
                    console.log('Closed the database connection.');
                });

                rl.close();
            });
        });
    });
}

// Start the process
addUser();
