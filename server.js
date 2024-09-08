const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();
const port = 3000;

// Middleware for parsing request bodies and handling sessions
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
    store: new SQLiteStore({ db: 'sessions.sqlite' }), // Specify the SQLite database for sessions
    secret: 'your_secret_key', // Use a secure secret key
    resave: false,
    saveUninitialized: false, // Only save session if there is data
    cookie: {
        maxAge: 24 * 60 * 60 * 1000, // Session will expire in 24 hours
        secure: false, // Set to true if using HTTPS
    }
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

//Main Page
app.get('/', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;

    const userSql = `SELECT name FROM users WHERE id = ?`;
    const dataSql = `SELECT users.name AS user_name, 
                            readers.reader_name,
                            family.family_name,
                            chaptersmaster.book || ' ' || chaptersmaster.chapter AS chapter_name,
                            user_chapters.timestamp
                     FROM user_chapters
                     INNER JOIN users ON user_chapters.user_id = users.id
                     INNER JOIN chaptersmaster ON user_chapters.chapter_id = chaptersmaster.id
                     INNER JOIN readers ON user_chapters.reader_id = readers.id
                     INNER JOIN family ON readers.family_id = family.id
                     WHERE users.id = ?`;

    const readerChapterCountSql = `SELECT readers.reader_name, COUNT(user_chapters.id) AS chapter_count
                                   FROM readers
                                   INNER JOIN family ON readers.family_id = family.id
                                   LEFT JOIN user_chapters ON user_chapters.reader_id = readers.id
                                   WHERE family.user_id = ?
                                   GROUP BY readers.id`;

    // Query to get the total number of chapters across all users
    const totalChaptersSql = `SELECT COUNT(*) AS total_chapters FROM user_chapters`;

    db.get(userSql, [userId], (err, userRow) => {
        if (err) {
            console.error(err.message);
            res.status(500).send('Error retrieving user');
            return;
        }

        const userName = userRow ? userRow.name : 'Guest';

        db.all(dataSql, [userId], (err, chapterRows) => {
            if (err) {
                console.error(err.message);
                res.status(500).send('Error retrieving data');
                return;
            }

            db.all(readerChapterCountSql, [userId], (err, readerCounts) => {
                if (err) {
                    console.error(err.message);
                    res.status(500).send('Error retrieving reader chapter counts');
                    return;
                }

                // Get the total chapter count across all users
                db.get(totalChaptersSql, [], (err, totalResult) => {
                    if (err) {
                        console.error('Error retrieving total chapter count:', err.message);
                        return res.status(500).send('Error retrieving total chapter count');
                    }

                    const totalChapters = totalResult ? totalResult.total_chapters : 0;

                    // Render the index page with all the required data
                    res.render('index', { 
                        userName, 
                        chapterRows, 
                        readerCounts, 
                        totalChapters  // Pass total chapter count to the template
                    });
                });
            });
        });
    });
});


// Render the record page with collapsible chapters list
app.get('/record', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    // SQL to get the readers associated with the user's family
    const familySql = `SELECT family.id FROM family WHERE user_id = ?`;
    const readersSql = `SELECT readers.id, readers.reader_name 
                        FROM readers 
                        INNER JOIN family ON readers.family_id = family.id
                        WHERE family.user_id = ?`;
    const chapterSql = `SELECT id, book, chapter FROM chaptersmaster ORDER BY id`;

    // Get the user's family ID
    db.get(familySql, [userId], (err, familyRow) => {
        if (err || !familyRow) {
            console.error('Error retrieving family:', err.message);
            return res.status(500).send('Error retrieving family');
        }

        // Fetch all readers in the family
        db.all(readersSql, [userId], (err, readers) => {
            if (err) {
                console.error('Error retrieving readers:', err.message);
                return res.status(500).send('Error retrieving readers');
            }

            // Fetch chapters for the form
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

                // Render the record page with readers and chapters
                res.render('record', { userName: req.session.userName, readers, chaptersByBook });
            });
        });
    });
});

// Handle form submission for recording chapters
app.post('/record', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const readerId = req.body.readerId;
    const startChapter = req.body.startChapterId;
    const endChapter = req.body.endChapterId;
    const bookName = req.body.bookName;

    console.log(`Received form submission: Reader ID - ${readerId}, Book - ${bookName}, Start Chapter - ${startChapter}, End Chapter - ${endChapter}`);
    if (!bookName) {
        return res.status(400).send('Book name is missing.');
    }
    if (!readerId || !startChapter || !endChapter) {
        return res.status(400).send('Missing required data.');
    }

    const startChapterId = parseInt(startChapter);
    const endChapterId = parseInt(endChapter);

    if (startChapterId > endChapterId) {
        console.error(`Error: Start chapter (${startChapterId}) cannot be greater than end chapter (${endChapterId}).`);
        return res.status(400).send('Invalid chapter range.');
    }

    const sql = `INSERT INTO user_chapters (user_id, reader_id, chapter_id) VALUES (?, ?, ?)`;
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
                stmt.run([userId, readerId, row.id], (err) => {
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

app.get('/manage', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    
    const userSql = `SELECT name FROM users WHERE id = ?`;
    db.get(userSql, [userId], (err, userRow) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Error retrieving user');
        }

    const userName = userRow ? userRow.name : 'Guest';

    // Fetch the family group for the logged-in user
    const familySql = `SELECT family.id as family_id, family.family_name, readers.id as reader_id, readers.reader_name
                       FROM family
                       LEFT JOIN readers ON family.id = readers.family_id
                       WHERE family.user_id = ?`;

    db.all(familySql, [userId], (err, rows) => {
        if (err) {
            console.error('Error retrieving family group:', err.message);
            return res.status(500).send('Error retrieving family group');
        }

        // If the family group exists, pass it to the view, otherwise set up a blank form for creating a family
        if (rows.length > 0) {
            const family = rows[0]; // All readers belong to the same family
            const readers = rows.map(row => ({ id: row.reader_id, name: row.reader_name }));
            res.render('manage', { userName, family, readers });
        } else {
            res.render('manage', { userName, family: null, readers: [] });
        }
    });
    });
});

// Handle form submission for adding a reader
app.post('/addReader', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const { familyId, readerName } = req.body;

    // Insert a new reader associated with the logged-in user's family
    const insertReaderSql = `INSERT INTO readers (family_id, reader_name) VALUES (?, ?)`;

    db.run(insertReaderSql, [familyId, readerName], function (err) {
        if (err) {
            console.error('Error adding reader:', err.message);
            return res.status(500).send('Error adding reader');
        }
        console.log(`Added new reader with ID ${this.lastID}`);
        res.redirect('/manage');
    });
});

// Handle form submission for creating a family
app.post('/createFamily', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const { familyName } = req.body;

    // Insert a new family for the logged-in user
    const createFamilySql = `INSERT INTO family (user_id, family_name) VALUES (?, ?)`;

    db.run(createFamilySql, [userId, familyName], function (err) {
        if (err) {
            console.error('Error creating family:', err.message);
            return res.status(500).send('Error creating family');
        }
        console.log(`Created new family with ID ${this.lastID}`);
        res.redirect('/manage');
    });
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Error logging out.');
        }
        res.redirect('/login');
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
