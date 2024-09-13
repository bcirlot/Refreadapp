const sqlite3 = require('sqlite3').verbose();

let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
    db.run(`
        ALTER TABLE users
        ADD COLUMN reset_token TEXT,
        ADD COLUMN reset_token_expiration INTEGER,
        ADD COLUMN role TEXT DEFAULT 'user'
      `, (err) => {
        if (err) {
          console.error('Error updating users table:', err);
        } else {
          console.log('Users table updated successfully');
        }
      });
});

