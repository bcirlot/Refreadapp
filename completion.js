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

// Create chapters_completion table without dropping it
const createCompletionTable = `
    CREATE TABLE IF NOT EXISTS chapters_completion (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reader_id INTEGER,
        chapter_id INTEGER,
        timestamp TEXT,
        completion_order INTEGER,
        completion_cycle INTEGER,
        points_claimed INTEGER DEFAULT 0
    );
`;

db.exec(createCompletionTable, (err) => {
    if (err) {
        console.error('Error creating chapters_completion table:', err.message);
        return;
    }

    console.log('chapters_completion table created successfully.');

    getLoopCountAndProcessCompletions();
});

function getLoopCountAndProcessCompletions() {
    // Step 1: Find the lowest occurrences for any chapter to determine how many completions
    const getMinOccurrencesSql = `
        SELECT MIN(chapter_count) AS lowest_occurrences 
        FROM (SELECT chapter_id, COUNT(*) AS chapter_count 
              FROM user_chapters GROUP BY chapter_id) AS chapter_counts
    `;

    // Step 2: Find the last recorded completion cycle
    const getLastCompletionCycleSql = `SELECT MAX(completion_cycle) AS last_cycle FROM chapters_completion`;

    db.get(getMinOccurrencesSql, [], (err, row) => {
        if (err) {
            console.error('Error retrieving the minimum occurrences:', err.message);
            return;
        }

        const loopCount = row.lowest_occurrences;
        console.log(`Total completion cycles found: ${loopCount}`);

        // Get the last recorded completion cycle
        db.get(getLastCompletionCycleSql, [], (err, cycleRow) => {
            if (err) {
                console.error('Error retrieving the last completion cycle:', err.message);
                return;
            }

            const lastCycle = cycleRow.last_cycle || 0; // If no cycle, start from 0
            console.log(`Last recorded completion cycle: ${lastCycle}`);

            // Process new completions starting from the next cycle
            processMultipleCompletions(loopCount, lastCycle + 1);
        });
    });
}

function processMultipleCompletions(loopCount, startingCycle) {
    for (let i = startingCycle; i <= loopCount; i++) {
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
                // Check if the chapter has already been recorded for this cycle
                const checkIfExistsSql = `
                    SELECT 1 FROM chapters_completion 
                    WHERE reader_id = ? AND chapter_id = ? AND completion_cycle = ?
                `;

                db.get(checkIfExistsSql, [row.reader_id, row.chapter_id, completionCycle], (err, result) => {
                    if (err) {
                        console.error('Error checking for existing chapter:', err.message);
                        return;
                    }

                    // If the chapter doesn't exist in this cycle, insert it
                    if (!result) {
                        const insertSql = `
                            INSERT INTO chapters_completion (reader_id, chapter_id, timestamp, completion_cycle, completion_order)
                            VALUES (?, ?, ?, ?, ?);
                        `;
                        db.run(insertSql, [row.reader_id, row.chapter_id, row.timestamp, completionCycle, 25 - index], (err) => {
                            if (err) {
                                console.error(`Error inserting completion data for cycle ${completionCycle}:`, err.message);
                            }
                        });
                    } else {
                        console.log(`Chapter ${row.chapter_id} already exists for cycle ${completionCycle}, skipping.`);
                    }
                });
            });
        });
    }
}

// Close the database connection once done
db.close((err) => {
    if (err) {
        return console.error(err.message);
    }
    console.log('Database connection closed.');
});
