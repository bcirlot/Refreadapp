const sqlite3 = require('sqlite3').verbose();

let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
    createReadersTable();
    createFamiliesTable();
});


function createReadersTable() {
    db.run(`CREATE TABLE IF NOT EXISTS readers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        family_id INTEGER, 
        reader_name TEXT
    )`, (err) => {
       if (err) {
           console.error(err.message);
           return;
       }
       console.log('Created readers table.');
   });
}
function createFamiliesTable() {
    db.run(`CREATE TABLE IF NOT EXISTS family (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, 
        family_name TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => {
       if (err) {
           console.error(err.message);
           return;
       }
       console.log('Created family table.');
   });
}