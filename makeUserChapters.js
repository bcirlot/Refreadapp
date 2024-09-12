
const sqlite3 = require('sqlite3').verbose();



// Create and connect to a database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
    clearUserChaptersTable();
});


function clearUserChaptersTable() {
    // Delete all existing data from the user_chapters table
    db.run(`DROP TABLE IF EXISTS user_chapters`, (err) => {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log('Cleared existing data from user_chapters table.');

        // After clearing data, recreate the table and insert new data
        createUserChaptersTable();
    });
}
function createUserChaptersTable() {
    // Create the user_chapters table
   db.run(`CREATE TABLE IF NOT EXISTS user_chapters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,   
        user_id INTEGER,
        reader_id INTEGER,
       chapter_id INTEGER,
       timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
       FOREIGN KEY (reader_id) REFERENCES readers(id) ON DELETE CASCADE,
       FOREIGN KEY(user_id) REFERENCES users(id),
       FOREIGN KEY(chapter_id) REFERENCES chaptersmaster(id)
   )`, (err) => {
       if (err) {
           console.error(err.message);
           return;
       }
       console.log('Created user_chapters table.');
   });
}