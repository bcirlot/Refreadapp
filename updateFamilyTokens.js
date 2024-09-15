const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

// Connect to your SQLite database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
});
// Function to generate a unique join token
function generateJoinToken() {
    return crypto.randomBytes(16).toString('hex'); // Generate a 16-byte random token (32-character hex string)
}

// Fetch all families from the database
db.all('SELECT id FROM family', (err, rows) => {
    if (err) {
        console.error('Error fetching families:', err.message);
        return;
    }

    // Iterate through each family and update its join_token
    rows.forEach((family) => {
        const token = generateJoinToken(); // Generate a new token
        db.run('UPDATE family SET join_token = ? WHERE id = ?', [token, family.id], (updateErr) => {
            if (updateErr) {
                console.error(`Error updating family with ID ${family.id}:`, updateErr.message);
            } else {
                console.log(`Updated family ID ${family.id} with join_token ${token}`);
            }
        });
    });
});

// Close the database after processing
db.close((closeErr) => {
    if (closeErr) {
        console.error('Error closing the database:', closeErr.message);
    } else {
        console.log('Database connection closed.');
    }
});
