const sqlite3 = require('sqlite3').verbose();

// Create and connect to a database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');

    // Query to join and display data from user_chapters, users, and chaptersmaster tables
    db.all(`
        SELECT 
            user_chapters.user_id, 
            users.name AS user_name, 
            user_chapters.chapter_id, 
            chaptersmaster.name AS chapter_name
        FROM 
            user_chapters
        INNER JOIN 
            users ON user_chapters.user_id = users.id
        INNER JOIN 
            chaptersmaster ON user_chapters.chapter_id = chaptersmaster.id
    `, [], (err, rows) => {
        if (err) {
            console.error(err.message);
            return;
        }

        // Ensure rows are not undefined
        if (rows) {
            rows.forEach((row) => {
                console.log(`User ID: ${row.user_id}, User Name: ${row.user_name}, Chapter ID: ${row.chapter_id}, Chapter Name: ${row.chapter_name}`);
            });
        }

        // Close the database connection after query
        db.close((err) => {
            if (err) {
                console.error(err.message);
                return;
            }
            console.log('Closed the database connection.');
        });
    });
});
