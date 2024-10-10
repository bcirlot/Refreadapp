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

// Function to track collective Bible completions and log the last 25 chapters
function processCollectiveBibleCompletions() {
    console.log('Starting processCollectiveBibleCompletions...');

    // Step 1: Get all the chapters and sort them by timestamp
    const allChaptersSql = `
    SELECT chapter_id, reader_id, timestamp 
    FROM user_chapters 
    ORDER BY timestamp ASC
    `;

    db.all(allChaptersSql, [], (err, allChapters) => {
        if (err) {
            console.error('Error retrieving chapters:', err.message);
            return res.status(500).send('Error retrieving chapters');
        }

        console.log('Total chapters retrieved:', allChapters.length);

        const totalBibleChapters = 1189;
        let chapterCounts = {};  // Track how many times each chapter has been read
        let chapterUsage = {};   // Track how many times each chapter has been used in a completion cycle
        let completionCycles = 0;

        // Initialize chapter usage tracking
        allChapters.forEach(chapter => {
            chapterUsage[chapter.chapter_id] = 0; // Initialize usage count for each chapter
        });

        console.log('Initialized chapter usage tracking for all chapters.');

        // Step 2: Process each reported chapter
        allChapters.forEach((chapter, index) => {
            const { chapter_id, reader_id, timestamp } = chapter;

            // Increment the count for this chapter
            if (!chapterCounts[chapter_id]) {
                chapterCounts[chapter_id] = 0;
            }
            chapterCounts[chapter_id] += 1;

            // Log chapter processing
            console.log(`Processing chapter ${chapter_id} from reader ${reader_id} (Index: ${index})`);

            // Mark the chapter as used for the current cycle
            chapterUsage[chapter_id] += 1;

            // Log chapter usage
            console.log(`Chapter ${chapter_id} usage in current cycle: ${chapterUsage[chapter_id]}`);

            // Check if a full cycle (1189 chapters) has been completed
            const chaptersUsedInCurrentCycle = Object.values(chapterUsage).filter(count => count === completionCycles + 1).length;
            console.log(`Chapters used in current cycle: ${chaptersUsedInCurrentCycle}`);

            if (chaptersUsedInCurrentCycle === totalBibleChapters) {
                // Increment the cycle count
                completionCycles++;
                console.log(`Completion cycle ${completionCycles} detected.`);

                // Step 3: Find the last 25 chapters for this cycle, based on the timestamp and update usage
                const last25Chapters = allChapters
                    .filter(c => chapterUsage[c.chapter_id] === completionCycles) // Only take chapters used in this specific cycle
                    .slice(-25);

                console.log(`Last 25 chapters for completion cycle ${completionCycles}:`, last25Chapters.map(c => c.chapter_id));

                // Log these chapters in the chapters_completion table
                last25Chapters.forEach((c, index) => {
                    const insertCompletionSql = `
                        INSERT INTO chapters_completion (reader_id, chapter_id, timestamp, completion_cycle, completion_order)
                        VALUES (?, ?, ?, ?, ?)
                    `;
                    db.run(insertCompletionSql, [c.reader_id, c.chapter_id, c.timestamp, completionCycles, 25 - index], (err) => {
                        if (err) {
                            console.error('Error logging completion chapter:', err.message);
                        } else {
                            console.log(`Logged chapter ${c.chapter_id} for completion cycle ${completionCycles}`);
                        }
                    });
                });
            }
        });

        // Close the database connection once done
        db.close((err) => {
            if (err) {
                return console.error(err.message);
            }
            console.log('Database connection closed.');
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
