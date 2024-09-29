import sqlite3 from 'sqlite3';
sqlite3.verbose();

// Open a database connection
const db = new sqlite3.Database('../mydatabase.db');

// Create tables for reading_plans and reader_plans
const createTables = () => {
    db.serialize(() => {
        // Create reading_plans tabl

        // Populate reading_plans with the Book of Revelation (assuming chapter IDs 1183 to 1189)
        const wholeBibleChapters = JSON.stringify([...Array(1189).keys()].map(i => i + 1));
        const insertRevelationPlan = db.prepare(`
            INSERT INTO reading_plans (name, chapter_ids) 
            VALUES (?, ?)
        `);

        insertRevelationPlan.run('Whole Bible', wholeBibleChapters, function (err) {
            if (err) {
                console.error('Error inserting Revelation reading plan:', err.message);
            } else {
                console.log(`Inserted Whole reading plan with ID ${this.lastID}`);
            }
        });

        insertRevelationPlan.finalize();
    });
};

// Close the database connection
const closeDatabase = () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing the database:', err.message);
        } else {
            console.log('Database connection closed.');
        }
    });
};

// Execute the script
createTables();
closeDatabase();
