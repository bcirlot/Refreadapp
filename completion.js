import sqlite3 from 'sqlite3';
sqlite3.verbose();
// Open database connection
let db = new sqlite3.Database('../mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the SQLite database.');
});
// Drop and create the chapters_completion table
const createCompletionTable = `
    DROP TABLE IF EXISTS chapters_completion;
    CREATE TABLE chapters_completion (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reader_id INTEGER,
        chapter_id INTEGER,
        timestamp TEXT,
        completion_order INTEGER,
        completion_cycle INTEGER,
        points_claimed INTEGER DEFAULT 0
    );
`;

function processMultipleCompletions(loopCount) {
    for (let i = 1; i <= loopCount; i++) {
        const completionCycle = i;

        // SQL query to get the nth occurrence of each chapter (based on completionCycle)
        const sqlQuery = `
            WITH RankedChapters AS (
                SELECT chapter_id, reader_id, timestamp, 
                ROW_NUMBER() OVER (PARTITION BY chapter_id ORDER BY timestamp ASC) AS rank 
                FROM user_chapters
            )
            SELECT chapter_id, reader_id, timestamp 
            FROM RankedChapters 
            WHERE rank = ? 
            ORDER BY timestamp DESC 
            LIMIT 25;
        `;

        db.all(sqlQuery, [completionCycle], (err, rows) => {
            if (err) {
                console.error(`Error fetching data for cycle ${completionCycle}:`, err.message);
                return;
            }

            console.log(`Processing completion cycle: ${completionCycle}`);

            // Process the rows for this cycle (for example, insert them into the completion table)
            rows.forEach((row, index) => {
                const insertSql = `
                    INSERT INTO chapters_completion (reader_id, chapter_id, timestamp, completion_cycle, completion_order)
                    VALUES (?, ?, ?, ?, ?);
                `;
                db.run(insertSql, [row.reader_id, row.chapter_id, row.timestamp, completionCycle, 25 - index], (err) => {
                    if (err) {
                        console.error(`Error inserting completion data for cycle ${completionCycle}:`, err.message);
                    }
                });
            });
        });
    }
}

// Set the number of cycles to process
const loopCount = 12;  // Change this to whatever number you need






// Execute the query to create the table
db.exec(createCompletionTable, (err) => {
    if (err) {
        console.error('Error creating chapters_completion table:', err.message);
        return;
    }

    console.log('chapters_completion table created successfully.');

    // Process collective Bible completions
    processMultipleCompletions(loopCount);
});
// Close the database connection once done
db.close((err) => {
    if (err) {
        return console.error(err.message);
    }
    console.log('Database connection closed.');
});
