import sqlite3 from 'sqlite3';
sqlite3.verbose();

// Open a database connection
const db = new sqlite3.Database('../mydatabase.db');

// Create tables for reading_plans and reader_plans
const createTables = () => {
    db.serialize(() => {
        // Create reading_plans table
        db.run(`
            CREATE TABLE IF NOT EXISTS reading_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                chapter_ids JSON NOT NULL
            )
        `);

        // Create reader_plans table
        db.run(`
            CREATE TABLE IF NOT EXISTS reader_plans (
                reader_id INTEGER NOT NULL,
                plan_id INTEGER NOT NULL,
                FOREIGN KEY(reader_id) REFERENCES readers(id),
                FOREIGN KEY(plan_id) REFERENCES reading_plans(id)
            )
        `);

        console.log('Tables created successfully.');

        // Populate reading_plans with the Book of Revelation (assuming chapter IDs 1183 to 1189)
        const revelationChapters = JSON.stringify([...Array(22).keys()].map(i => i + 1168));
        const insertRevelationPlan = db.prepare(`
            INSERT INTO reading_plans (name, chapter_ids) 
            VALUES (?, ?)
        `);

        insertRevelationPlan.run('Book of Revelation', revelationChapters, function (err) {
            if (err) {
                console.error('Error inserting Revelation reading plan:', err.message);
            } else {
                console.log(`Inserted Revelation reading plan with ID ${this.lastID}`);
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
