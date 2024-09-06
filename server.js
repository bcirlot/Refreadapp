const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();
const port = 3000;

// Middleware for parsing request bodies and handling sessions
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Set static folder for serving static files
app.use(express.static(path.join(__dirname, 'public')));

// Set up view engine for EJS
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Connect to the SQLite database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the SQLite database.');
});

// Render the login page
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// Handle login form submission
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const sql = `SELECT * FROM users WHERE email = ?`;
    db.get(sql, [email], (err, user) => {
        if (err) {
            console.error(err.message);
            res.render('login', { error: 'An error occurred, please try again.' });
            return;
        }

        if (!user) {
            res.render('login', { error: 'Invalid email or password.' });
            return;
        }

        // Compare the entered password with the stored hashed password
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error(err.message);
                res.render('login', { error: 'An error occurred, please try again.' });
                return;
            }

            if (isMatch) {
                req.session.userId = user.id;
                req.session.userName = user.name;
                res.redirect('/');
            } else {
                res.render('login', { error: 'Invalid email or password.' });
            }
        });
    });
});

// Display user's recorded chapters
app.get('/', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const userSql = `SELECT name FROM users WHERE id = ?`;
    const dataSql = `SELECT users.name as user_name, 
                            chaptersmaster.book || ' ' || chaptersmaster.chapter as chapter_name,
                            user_chapters.timestamp -- Include timestamp from user_chapters table
                     FROM user_chapters
                     INNER JOIN users ON user_chapters.user_id = users.id
                     INNER JOIN chaptersmaster ON user_chapters.chapter_id = chaptersmaster.id
                     WHERE users.id = ?`;

    db.get(userSql, [userId], (err, userRow) => {
        if (err) {
            console.error(err.message);
            res.status(500).send('Error retrieving user');
            return;
        }

        const userName = userRow ? userRow.name : 'Guest'; // Fallback to 'Guest' if name is not found

        // Fetch the chapters recorded by the user
        db.all(dataSql, [userId], (err, rows) => {
            if (err) {
                console.error(err.message);
                res.status(500).send('Error retrieving data');
                return;
            }

            res.render('index', { userName, data: rows });
        });
    });
});

// Render the record page with collapsible chapters list
app.get('/record', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const userSql = `SELECT name FROM users WHERE id = ?`;
    const chapterSql = `SELECT id, book, chapter FROM chaptersmaster ORDER BY id`;

    db.get(userSql, [userId], (err, userRow) => {
        if (err) {
            console.error('Error retrieving user:', err.message);
            return res.status(500).send('Error retrieving user');
        }

        const userName = userRow ? userRow.name : 'Guest';

        db.all(chapterSql, [], (err, chapters) => {
            if (err) {
                console.error('Error retrieving chapters:', err.message);
                return res.status(500).send('Error retrieving chapters');
            }

            // Group chapters by book
            const chaptersByBook = {};
            chapters.forEach(chapter => {
                const book = chapter.book.trim();
                if (!chaptersByBook[book]) {
                    chaptersByBook[book] = [];
                }
                chaptersByBook[book].push({ id: chapter.id, name: `${book} ${chapter.chapter}` });
            });

            res.render('record', { userName, chaptersByBook });
        });
    });
});

// Handle form submission for recording chapters
app.post('/record', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const startChapter = req.body.startChapterId;
    const endChapter = req.body.endChapterId;
    const bookName = req.body.bookName;

    console.log(`Received form submission: Book - ${bookName}, Start Chapter - ${startChapter}, End Chapter - ${endChapter}`);
    if (!bookName) {
        return res.status(400).send('Book name is missing.');
    }
    const startChapterId = parseInt(startChapter);
    const endChapterId = parseInt(endChapter);

    if (startChapterId > endChapterId) {
        console.error(`Error: Start chapter (${startChapterId}) cannot be greater than end chapter (${endChapterId}).`);
        return res.status(400).send('Invalid chapter range.');
    }

    const sql = `INSERT INTO user_chapters (user_id, chapter_id) VALUES (?, ?)`;
    const stmt = db.prepare(sql);

    let pendingOperations = 0;
    let hasErrorOccurred = false;

    for (let chapterId = startChapterId; chapterId <= endChapterId; chapterId++) {
        const chapterName = `${bookName} ${chapterId}`;
        pendingOperations++;

        console.log(`Finding chapter in the database: ${chapterName}`); // Log the chapter being searched in the DB

        db.get(`SELECT id FROM chaptersmaster WHERE book = ? AND chapter = ?`, [bookName, chapterId], (err, row) => {
            if (err) {
                console.error(`Error finding chapter ${chapterName}:`, err.message);
                hasErrorOccurred = true;
            } else if (row) {
                console.log(`Found chapter ID for ${chapterName}: ${row.id}`); // Log found chapter ID
                stmt.run([userId, row.id], (err) => {
                    if (err) {
                        console.error(`Error inserting chapter ${chapterId}:`, err.message);
                        hasErrorOccurred = true;
                    }
                });
            } else {
                console.error(`Chapter ${chapterName} not found.`);
                hasErrorOccurred = true;
            }

            pendingOperations--;

            if (pendingOperations === 0) {
                finalizeStatement();
            }
        });
    }

    function finalizeStatement() {
        stmt.finalize((err) => {
            if (err) {
                console.error('Error finalizing statement:', err.message);
                return res.status(500).send('Error recording chapters.');
            }

            if (hasErrorOccurred) {
                console.log('Some errors occurred during the process.');
                return res.status(500).send('Error occurred while recording some chapters.');
            }

            console.log('Chapters successfully recorded.');
            res.redirect('/');
        });
    }
});

app.get('/admin', (req, res) => {

});



// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
