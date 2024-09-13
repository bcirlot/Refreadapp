//This script created the chaptersmaster table the first time from the csv "bibletaxonomy.csv"
//The problem was the that csv lists the bible by verse, whereas we needed it
//to be listed by chapter. So this script takes that input and outputs the database
//of chapters giving each chapter a unique id based on order of chapters in the bible
//it also gives the book name, chaper number, verse count, and textament for each 
//chapter in the whole bible. There are 1189 rows. I also exported this database 
//as biblechapters.csv for ease of use in the future.

const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const csv = require('csv-parser');

// Create and connect to a database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
    clearChaptersTable();
});

//Code for clearing if already made, creating, and populating the chaptersmaster table with all the necessary data
function clearChaptersTable() {
    db.run(`DROP TABLE IF EXISTS chaptersmaster`, (err) => {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log('Cleared existing data from chaptersmaster table.');
        createChaptersTable();
    });
}
function createChaptersTable() {
    db.run(`CREATE TABLE IF NOT EXISTS chaptersmaster (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        book TEXT,
        chapter INTEGER,
        testament TEXT,
        verses INTEGER
    )`, (err) => {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log('Created chaptersmaster table.');

        // After creating the table, insert the data from the CSV file
        insertChaptersFromCSV();
    });
}
function insertChaptersFromCSV() {
    const filePath = 'bibletaxonomy.csv';
    const chapters = {};
    fs.createReadStream(filePath)
        .pipe(csv({
            mapHeaders: ({ header, index }) => header.trim()
        }))
        .on('data', (row) => {
            const Book = row['Book']?.trim();
            const Chapter = row['Chapter']?.trim();
            const Verse = row['Verse']?.trim();
            if (!Book || !Chapter || !Verse) {
                console.error('Invalid row format:', row);
                return; // Skip invalid rows
            }
            const chapterKey = `${Book}-${Chapter}`; // Unique key for each book-chapter combo

            // If the chapter already exists in the object, increment the verse count
            if (chapters[chapterKey]) {
                chapters[chapterKey].verses += 1;
            } else {
                // Otherwise, initialize the chapter with 1 verse
                chapters[chapterKey] = {
                    book: Book,
                    chapter: parseInt(Chapter, 10), // Ensure chapter is an integer
                    testament: inferTestament(Book), // Infer testament
                    verses: 1,
                };
            }
        })
        .on('end', () => {
            // Prepare the insert statement
            const stmt = db.prepare(`INSERT INTO chaptersmaster (book, chapter, testament, verses) VALUES (?, ?, ?, ?)`);

            // Insert each chapter and its verse count into the database
            Object.values(chapters).forEach((chapter) => {
                console.log('Inserting chapter:', chapter); // Log each insert for debugging
                stmt.run([chapter.book, chapter.chapter, chapter.testament, chapter.verses], (err) => {
                    if (err) {
                        console.error(`Error inserting row: ${err.message}`);
                    }
                });
            });

            stmt.finalize();
            console.log('All chapters inserted.');
            db.close();
        })
        .on('error', (err) => {
            console.error(`Error reading CSV file: ${err.message}`);
        });
}
function inferTestament(bookName) {
    const oldTestamentBooks = [
        'Genesis', 'Exodus', 'Leviticus', 'Numbers', 'Deuteronomy', 'Joshua', 'Judges', 'Ruth', '1 Samuel', '2 Samuel', '1 Kings', '2 Kings', '1 Chronicles', '2 Chronicles', 'Ezra', 'Nehemiah', 'Esther', 'Job', 'Psalms', 'Proverbs', 'Ecclesiastes', 'Song of Solomon', 'Isaiah', 'Jeremiah', 'Lamentations', 'Ezekiel', 'Daniel', 'Hosea', 'Joel', 'Amos', 'Obadiah', 'Jonah', 'Micah', 'Nahum', 'Habakkuk', 'Zephaniah', 'Haggai', 'Zechariah', 'Malachi'
    ];
    if (oldTestamentBooks.includes(bookName)) {
        return 'Old';
    } else {
        return 'New';
    }
}