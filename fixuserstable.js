const sqlite3 = require('sqlite3').verbose();

let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
    db.run('ALTER TABLE users ADD COLUMN reset_token TEXT', (err) => {
        if (err) {
          console.error('Error adding reset_token column:', err);
        } else {
          console.log('reset_token column added successfully');
        }
      });
      
      db.run('ALTER TABLE users ADD COLUMN reset_token_expiration INTEGER', (err) => {
        if (err) {
          console.error('Error adding reset_token_expiration column:', err);
        } else {
          console.log('reset_token_expiration column added successfully');
        }
      });
      
      db.run('ALTER TABLE users ADD COLUMN role TEXT DEFAULT "user"', (err) => {
        if (err) {
          console.error('Error adding role column:', err);
        } else {
          console.log('role column added successfully');
        }
      });
});

