import sqlite3 from 'sqlite3';
sqlite3.verbose();  // Adjust to your database if necessary

// Open your database
const db = new sqlite3.Database('../mydatabase.db');  // Change the database file path

// Function to calculate and add points for each reader
function fixReaderPoints() {
    // Find readers who have no points entry in userpoints
    const missingUserPointsSql = `
        SELECT readers.id AS reader_id, readers.reader_name
        FROM readers
        LEFT JOIN userpoints ON readers.id = userpoints.reader_id
        WHERE userpoints.reader_id IS NULL
    `;

    db.all(missingUserPointsSql, [], (err, readers) => {
        if (err) {
            console.error('Error retrieving readers without userpoints:', err.message);
            return;
        }

        readers.forEach((reader) => {
            // For each reader without points, check if they have chapters reported
            const reportedChaptersSql = `
                SELECT chapter_id, COUNT(*) AS times_reported
                FROM user_chapters
                WHERE reader_id = ?
                GROUP BY chapter_id
            `;

            db.all(reportedChaptersSql, [reader.reader_id], (err, chapters) => {
                if (err) {
                    console.error('Error retrieving chapters for reader:', err.message);
                    return;
                }

                let totalPointsToAdd = 0;

                if (chapters.length === 0) {
                    // If the reader has no chapters reported, give them 1 point
                    totalPointsToAdd = 1;
                    console.log(`Reader ${reader.reader_name} has no chapters, assigning 1 point.`);
                } else {
                    // If the reader has chapters, calculate points:
                    chapters.forEach((chapter) => {
                        if (chapter.times_reported === 1) {
                            totalPointsToAdd += 5;  // Unique chapter, 5 points
                        } else {
                            totalPointsToAdd += 1;  // Repeated chapter, 1 point
                        }
                    });
                    console.log(`Reader ${reader.reader_name} has ${chapters.length} chapters, assigning ${totalPointsToAdd} points.`);
                }

                // Insert the points into the userpoints table for the reader
                const insertUserPointsSql = `INSERT INTO userpoints (reader_id, user_points) VALUES (?, ?)`;

                db.run(insertUserPointsSql, [reader.reader_id, totalPointsToAdd], (err) => {
                    if (err) {
                        console.error(`Error inserting points for reader ${reader.reader_name}:`, err.message);
                    } else {
                        console.log(`Assigned ${totalPointsToAdd} points to reader ${reader.reader_name}.`);
                    }
                });
            });
        });
    });
}

// Call the function to fix reader points
fixReaderPoints();

// Close the database connection once the operation is done
db.close((err) => {
    if (err) {
        console.error('Error closing the database connection:', err.message);
    } else {
        console.log('Database connection closed.');
    }
});
