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

function updateCompletionCycles() {
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
            processNewCompletions(loopCount, lastCycle + 1);
        });
    });
}

function processNewCompletions(loopCount, startingCycle) {
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

            console.log(`Processing new completion cycle: ${completionCycle}`);

            // Insert new rows into the chapters_completion table
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

// Execute the update
updateCompletionCycles();

// Close the database connection once done
db.close((err) => {
    if (err) {
        return console.error(err.message);
    }
    console.log('Database connection closed.');
});
