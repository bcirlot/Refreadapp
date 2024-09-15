const sqlite3 = require('sqlite3').verbose();

// Create and connect to a database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
    
});

db.run(`
    UPDATE users
    SET family_id = (
        SELECT family.id
        FROM family
        WHERE family.user_id = users.id
    )
    WHERE EXISTS (
        SELECT 1
        FROM family
        WHERE family.user_id = users.id
    )
`, (err) => {
    if (err) {
        console.error('Error updating users with family_id:', err.message);
    } else {
        console.log('Successfully updated family_id for all users');
    }
    db.close();
});
