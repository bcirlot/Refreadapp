const sqlite3 = require('sqlite3').verbose();
const readline = require('readline');

// Create and connect to a database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
});

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// Function to link user and chapter
function linkUserToChapter(userName, chapterName) {
    let userId;
    let chapterId;

    // Find the user ID
    db.get(`SELECT id FROM users WHERE name = ?`, [userName], (err, row) => {
        if (err) {
            console.error(err.message);
            rl.close();
            return;
        }
        if (row) {
            userId = row.id;
            console.log(`Found user ID: ${userId}`);

            // Find the chapter ID
            db.get(`SELECT id FROM chaptersmaster WHERE name = ?`, [chapterName], (err, row) => {
                if (err) {
                    console.error(err.message);
                    rl.close();
                    return;
                }
                if (row) {
                    chapterId = row.id;
                    console.log(`Found chapter ID: ${chapterId}`);

                    // Insert into the user_chapters table
                    db.run(`INSERT INTO user_chapters (user_id, chapter_id) VALUES (?, ?)`, [userId, chapterId], function(err) {
                        if (err) {
                            console.error(err.message);
                        } else {
                            console.log(`Linked user ${userName} with chapter ${chapterName}`);
                        }
                        rl.close();
                        db.close();
                    });
                } else {
                    console.log(`Chapter '${chapterName}' not found.`);
                    rl.close();
                    db.close();
                }
            });
        } else {
            console.log(`User '${userName}' not found.`);
            rl.close();
            db.close();
        }
    });
}

// Prompt the user for input
rl.question('Enter the user name: ', (userName) => {
    rl.question('Enter the chapter name: ', (chapterName) => {
        linkUserToChapter(userName, chapterName);
    });
});
