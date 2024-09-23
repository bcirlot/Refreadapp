import sqlite3 from 'sqlite3';
sqlite3.verbose();

// Open a database connection
const db = new sqlite3.Database('../mydatabase.db');

const ntChapters = JSON.stringify([...Array(260).keys()].map(i => i + 930));
const insertNTPlan = db.prepare(`
    INSERT INTO reading_plans (name, chapter_ids) 
    VALUES (?, ?)
`);

insertNTPlan.run('New Testament Plan', ntChapters, function (err) {
    if (err) {
        console.error('Error inserting Revelation reading plan:', err.message);
    } else {
        console.log(`Inserted Revelation reading plan with ID ${this.lastID}`);
    }
});

insertNTPlan.finalize();