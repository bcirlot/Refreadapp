const sqlite3 = require('sqlite3').verbose();

// Create and connect to a database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
    clearUserPointsTable();
});
function clearUserPointsTable() {
    db.run(`DROP TABLE IF EXISTS userpoints`, (err) => {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log('Cleared existing data from userpoints table.');

        // After clearing data, recreate the table and insert new data
        createUserPointsTable();
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