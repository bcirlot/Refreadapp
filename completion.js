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
        completion_cycle INTEGER,  -- New column to track the cycle
        points_claimed INTEGER DEFAULT 0
    );
`;

// Function to track collective Bible completions and log the last 25 chapters
function processCollectiveBibleCompletions() {
    // Query to get all chapter reports, ordered by timestamp
    const chapterReportsSql = `
        SELECT uc.reader_id, uc.chapter_id, uc.timestamp
        FROM user_chapters uc
        ORDER BY uc.timestamp ASC
    `;

    db.all(chapterReportsSql, [], (err, rows) => {
        if (err) {
            console.error('Error retrieving chapter reports:', err.message);
            return;
        }

        // Initialize variables to track completions
        let collectiveChaptersCompleted = new Set();
        let completionCycles = 0;  // Track the completion cycles
        let last25Chapters = [];

        rows.forEach((row) => {
            const { reader_id, chapter_id, timestamp } = row;

            // Add chapter to the collective set of completed chapters
            collectiveChaptersCompleted.add(chapter_id);

            // Track this chapter for potential inclusion in the last 25
            last25Chapters.push({ reader_id, chapter_id, timestamp });

            // Keep the array at 25 elements max (removing the oldest if it exceeds 25)
            if (last25Chapters.length > 25) {
                last25Chapters.shift();
            }

            // Check if we have a full Bible completion (all 1189 chapters have been reported)
            if (collectiveChaptersCompleted.size === 1189) {
                // Increment completion cycle count
                completionCycles += 1;

                console.log(`Collective Bible completion cycle #${completionCycles} found!`);

                // Log the last 25 chapters of this completion cycle
                last25Chapters.forEach((chapter, index) => {
                    const completionOrder = 25 - index; // 1 for the last chapter, 25 for the earliest of the 25
                    const insertCompletionSql = `
                        INSERT INTO chapters_completion (reader_id, chapter_id, timestamp, completion_order, completion_cycle, points_claimed)
                        VALUES (?, ?, ?, ?, ?, 0)
                    `;
                    db.run(insertCompletionSql, [chapter.reader_id, chapter.chapter_id, chapter.timestamp, completionOrder, completionCycles], (err) => {
                        if (err) {
                            console.error('Error inserting completion chapter:', err.message);
                        }
                    });
                });

                // Reset for the next cycle
                collectiveChaptersCompleted.clear(); // Clear the set of completed chapters
                last25Chapters = []; // Reset the last 25 chapters
                console.log('Completed chapters set cleared after cycle #' + completionCycles);

            }
        });

        console.log('Collective Bible completions processed.');

        // Close the database connection
        db.close((err) => {
            if (err) {
                console.error('Error closing the database:', err.message);
            } else {
                console.log('Database connection closed.');
            }
        });
    });
}

// Execute the query to create the table
db.exec(createCompletionTable, (err) => {
    if (err) {
        console.error('Error creating chapters_completion table:', err.message);
        return;
    }

    console.log('chapters_completion table created successfully.');

    // Process collective Bible completions
    processCollectiveBibleCompletions();
});
