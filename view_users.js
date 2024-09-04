const sqlite3 = require('sqlite3').verbose();

// Connect to the SQLite database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
});

// Query and display all users
db.all(`SELECT * FROM users`, [], (err, rows) => {
    if (err) {
        console.error(err.message);
        return;
    }
    
    console.log('List of all users:');
    rows.forEach((row) => {
        console.log(`ID: ${row.id}, Name: ${row.name}, Email: ${row.email}`);
    });
    
    // Close the database connection
    db.close((err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('Closed the database connection.');
    });
});
