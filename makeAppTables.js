const sqlite3 = require('sqlite3').verbose();

let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
    createReadersTable();
    createFamiliesTable();
    createUserPointsTable();
    createLevelsTable();
});


function createReadersTable() {
    db.run(`CREATE TABLE IF NOT EXISTS readers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        family_id INTEGER, 
        reader_name TEXT,
        current_level_id INTEGER,
        FOREIGN KEY(current_level_id) REFERENCES levels(id)
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

function createUserPointsTable() {
    db.run(`CREATE TABLE IF NOT EXISTS userpoints (
        reader_id INTEGER,
        user_points INTEGER, 
        FOREIGN KEY(reader_id) REFERENCES readers(id)
    )`, (err) => {
       if (err) {
           console.error(err.message);
           return;
       }
       console.log('Created userpoints table.');
   });
}
function createLevelsTable () {
    db.run(`CREATE TABLE levels (
        id INTEGER PRIMARY KEY,
        level_name TEXT NOT NULL,
        min_points INTEGER NOT NULL
    )`, (err) => {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log('Created levels table.');
    });
}
