// Import the sqlite3 module
const sqlite3 = require('sqlite3').verbose();

// Create and connect to a database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');

    // Create the table once connected
    createUserTable();
});

function createUserTable() {
    // Create the users table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT
    )`, (err) => {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log('Created users table.');

        // After creating the table, insert some data
        insertData();
    });
}

function insertData() {
    // Insert a row of data into the users table
    db.run(`INSERT INTO users (name, email) VALUES (?, ?)`, ['John Doe', 'john.doe@example.com'], function(err) {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log(`A row has been inserted with rowid ${this.lastID}`);

        // After inserting data, query the table
        queryData();
    });
}

function queryData() {
    // Query all rows from the users table
    db.all(`SELECT * FROM users`, [], (err, rows) => {
        if (err) {
            console.error(err.message);
            return;
        }

        // Ensure rows are not undefined
        if (rows) {
            rows.forEach((row) => {
                console.log(row);
            });
        }

        // Close the database connection after query
        closeDatabase();
    });
}

function closeDatabase() {
    // Close the database connection
    db.close((err) => {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log('Closed the database connection.');
    });
}
