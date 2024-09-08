const bcrypt = require('bcrypt');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();


// Create and connect to a database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
    clearUserTable();
});

//Code for clearing if already made, creating, and populating the chaptersmaster table with all the necessary data
//moved all the functions for creating the chapters database into makechaptersmaster.js
// function clearChaptersTable() {
//     // Drop the chaptersmaster table if it exists
//     db.run(`DROP TABLE IF EXISTS chaptersmaster`, (err) => {
//         if (err) {
//             console.error(err.message);
//             return;
//         }
//         console.log('Cleared existing data from chaptersmaster table.');
//         createChaptersTable();
//     });
// }
// function createChaptersTable() {
//     db.run(`CREATE TABLE IF NOT EXISTS chaptersmaster (
//         id INTEGER PRIMARY KEY AUTOINCREMENT,
//         book TEXT,
//         chapter INTEGER,
//         testament TEXT,
//         verses INTEGER
//     )`, (err) => {
//         if (err) {
//             console.error(err.message);
//             return;
//         }
//         console.log('Created chaptersmaster table.');

//         // After creating the table, insert the data from the CSV file
//         insertChaptersFromCSV();
//     });
// }
// function insertChaptersFromCSV() {
//     const filePath = 'bibletaxonomy.csv'; // Update with the correct path

//     // Create an empty object to store chapters and count verses
//     const chapters = {};

//     // Read the CSV file
//     fs.createReadStream(filePath)
//         .pipe(csv({
//             mapHeaders: ({ header, index }) => header.trim() // Ensure headers are trimmed
//         }))
//         .on('data', (row) => {
//             // Log the actual row to debug issues with undefined values
//             console.log('Full row object:', row);

//             // Trim values and log each key-value pair for debugging
//             const Book = row['Book']?.trim();
//             const Chapter = row['Chapter']?.trim();
//             const Verse = row['Verse']?.trim();

//             // Log extracted values to debug
//             console.log(`Book: ${Book}, Chapter: ${Chapter}, Verse: ${Verse}`);

//             if (!Book || !Chapter || !Verse) {
//                 console.error('Invalid row format:', row);
//                 return; // Skip invalid rows
//             }

//             const chapterKey = `${Book}-${Chapter}`; // Unique key for each book-chapter combo

//             // If the chapter already exists in the object, increment the verse count
//             if (chapters[chapterKey]) {
//                 chapters[chapterKey].verses += 1;
//             } else {
//                 // Otherwise, initialize the chapter with 1 verse
//                 chapters[chapterKey] = {
//                     book: Book,
//                     chapter: parseInt(Chapter, 10), // Ensure chapter is an integer
//                     testament: inferTestament(Book), // Infer testament
//                     verses: 1,
//                 };
//             }
//         })
//         .on('end', () => {
//             // Prepare the insert statement
//             const stmt = db.prepare(`INSERT INTO chaptersmaster (book, chapter, testament, verses) VALUES (?, ?, ?, ?)`);

//             // Insert each chapter and its verse count into the database
//             Object.values(chapters).forEach((chapter) => {
//                 console.log('Inserting chapter:', chapter); // Log each insert for debugging
//                 stmt.run([chapter.book, chapter.chapter, chapter.testament, chapter.verses], (err) => {
//                     if (err) {
//                         console.error(`Error inserting row: ${err.message}`);
//                     }
//                 });
//             });

//             stmt.finalize();
//             console.log('All chapters inserted.');
//             db.close();
//         })
//         .on('error', (err) => {
//             console.error(`Error reading CSV file: ${err.message}`);
//         });
// }
// function inferTestament(bookName) {
//     const oldTestamentBooks = [
//         'Genesis', 'Exodus', 'Leviticus', 'Numbers', 'Deuteronomy', 'Joshua', 'Judges', 'Ruth', '1 Samuel', '2 Samuel', '1 Kings', '2 Kings', '1 Chronicles', '2 Chronicles', 'Ezra', 'Nehemiah', 'Esther', 'Job', 'Psalms', 'Proverbs', 'Ecclesiastes', 'Song of Solomon', 'Isaiah', 'Jeremiah', 'Lamentations', 'Ezekiel', 'Daniel', 'Hosea', 'Joel', 'Amos', 'Obadiah', 'Jonah', 'Micah', 'Nahum', 'Habakkuk', 'Zephaniah', 'Haggai', 'Zechariah', 'Malachi'
//         // Add all Old Testament book names here...
//     ];

//     if (oldTestamentBooks.includes(bookName)) {
//         return 'Old';
//     } else {
//         return 'New';
//     }
// }

//Code for clearing, creating, and populating the users table (this needs to be removed in view of a user registration option)
function clearUserTable() {
    // Delete all existing data from the chaptersmaster table
    db.run(`DROP TABLE IF EXISTS users`, (err) => {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log('Cleared existing data from chaptersmaster table.');

        // After clearing data, recreate the table and insert new data
        createUserTable();
    });
}
function createUserTable() {
    // Create the users table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT,
        password TEXT
    )`, (err) => {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log('Created users table.');

        // After creating the table, insert some data
        insertUserData();
    });
}
function insertUserData() {
    const users = [
        { name: 'Alice Johnson', email: 'alice.johnson@example.com', password: 'password1' },
        { name: 'Bob Smith', email: 'bob.smith@example.com', password: 'password2' },
        { name: 'Charlie Brown', email: 'charlie.brown@example.com', password: 'password3' },
        { name: 'Diana Prince', email: 'diana.prince@example.com', password: 'password4' },
        { name: 'Ethan Hunt', email: 'ethan.hunt@example.com', password: 'password5' },
        { name: 'Fiona Gallagher', email: 'fiona.gallagher@example.com', password: 'password6' },
        { name: 'George Michael', email: 'george.michael@example.com', password: 'password7' },
        { name: 'Hannah Montana', email: 'hannah.montana@example.com', password: 'password8' },
        { name: 'Isaac Newton', email: 'isaac.newton@example.com', password: 'password9' },
        { name: 'Julia Roberts', email: 'julia.roberts@example.com', password: 'password10' }
    ];
    
    // Insert the users into the database
    users.forEach(user => {
        bcrypt.hash(user.password, 10, (err, hash) => {
            if (err) {
                console.error(err.message);
                return;
            }
            db.run(`INSERT INTO users (name, email, password) VALUES (?, ?, ?)`, [user.name, user.email, hash], function(err) {
                if (err) {
                    console.error(err.message);
                } else {
                    console.log(`A row has been inserted with rowid ${this.lastID}: ${user.name}, ${user.email}`);
                }
            });
        });
    });
    
}

//code for creating the table to user reading reports that will be populated by the server.js and record.ejs code
//moved to makeUserChapters.js
// function clearUserChaptersTable() {
//     // Delete all existing data from the chaptersmaster table
//     db.run(`DROP TABLE IF EXISTS user_chapters`, (err) => {
//         if (err) {
//             console.error(err.message);
//             return;
//         }
//         console.log('Cleared existing data from user_chapters table.');

//         // After clearing data, recreate the table and insert new data
//         createUserChaptersTable();
//     });
// }
// function createUserChaptersTable() {
//     // Create the user_chapters table
//    db.run(`CREATE TABLE IF NOT EXISTS user_chapters (
//         id INTEGER PRIMARY KEY AUTOINCREMENT,   
//         user_id INTEGER,
//        chapter_id INTEGER,
//        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
//        FOREIGN KEY(user_id) REFERENCES users(id),
//        FOREIGN KEY(chapter_id) REFERENCES chaptersmaster(id)
//    )`, (err) => {
//        if (err) {
//            console.error(err.message);
//            return;
//        }
//        console.log('Created user_chapters table.');
//    });
// }


//working towards readers instead of users being the thing reporting chapters
//the idea is the family is the same as the first user in that family so i will
//make them related by the firsst users' user id.

//Presently these functions are in tables.js
// function createReadersTable() {
//     db.run(`CREATE TABLE IF NOT EXISTS readers (
//         id INTEGER PRIMARY KEY AUTOINCREMENT,
//         family_id INTEGER, 
//         reader_name TEXT
//     )`, (err) => {
//        if (err) {
//            console.error(err.message);
//            return;
//        }
//        console.log('Created readers table.');
//    });
// }
// function createFamiliesTable() {
//     db.run(`CREATE TABLE IF NOT EXISTS family (
//         id INTEGER PRIMARY KEY AUTOINCREMENT,
//         user_id INTEGER, 
//         family_name TEXT,
//         FOREIGN KEY(user_id) REFERENCES users(id)
//     )`, (err) => {
//        if (err) {
//            console.error(err.message);
//            return;
//        }
//        console.log('Created family table.');
//    });
// }

function closeDatabase() {
    // Close the database connection
    db.close((err) => {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log('Closed the database connection.');
    });
}

