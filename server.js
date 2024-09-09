const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const path = require('path');
require('dotenv').config();
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const app = express();
const port = 3000;

// Middleware for parsing request bodies and handling sessions
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
    store: new SQLiteStore({ db: 'sessions.sqlite' }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        secure: false,
    }
}));

// Create a transporter for Zoho Mail
const transporter = nodemailer.createTransport({
    host: 'smtp.zoho.com',
    port: 465, // or 587 for TLS
    secure: true, // use SSL
    auth: {
        user: process.env.ZOHO_USER, 
        pass: process.env.ZOHO_PASS 
    },
});

// Verify the transporter connection
transporter.verify((error, success) => {
    if (error) {
        console.error('Error with transporter setup:', error);
    } else {
        console.log('Nodemailer is ready to send emails');
    }
});

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


// Route to handle user registration
app.post('/register', (req, res) => {
    const { name, email, password } = req.body;

    // Check if the email is already registered
    const checkEmailSql = `SELECT * FROM users WHERE email = ?`;
    db.get(checkEmailSql, [email], (err, row) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Error checking email');
        }

        if (row) {
            // If the email is already registered, show an error message
            return res.render('login', { error: 'Email already in use. Please log in.' });
        }

        // Hash the password
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send('Error hashing password');
            }

            // Insert the new user into the database
            const insertUserSql = `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`;
            db.run(insertUserSql, [name, email, hashedPassword], function (err) {
                if (err) {
                    console.error(err.message);
                    return res.status(500).send('Error registering user');
                }

                // Automatically log the user in after registration
                req.session.userId = this.lastID;
                req.session.userName = name;

                // Redirect to the main page
                res.redirect('/');
            });
        });
    });
});

// Render the forgot password page
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { error: null });
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    const token = crypto.randomBytes(20).toString('hex');

    // Check if email exists in the database
    const sql = `SELECT * FROM users WHERE email = ?`;
    db.get(sql, [email], (err, user) => {
        if (err || !user) {
            return res.status(400).send('Email does not exist');
        }

        // Store token and expiration time in the database
        const tokenExpiration = Date.now() + 3600000; // 1 hour
        const updateSql = `UPDATE users SET reset_token = ?, reset_token_expiration = ? WHERE email = ?`;
        db.run(updateSql, [token, tokenExpiration, email], (err) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send('Error generating reset link');
            }

            // Send reset email using the global transporter
            const resetLink = `http://localhost:3000/reset-password/${token}`;

            const mailOptions = {
                from: 'reformationreading@thesquarechurch.com', // Explicitly set the sender
                to: email,
                subject: 'Password Reset',
                text: `Click this link to reset your password: ${resetLink}`
            };

            transporter.sendMail(mailOptions, (err, info) => {
                if (err) {
                    console.error('Error sending email:', err.message);
                    return res.status(500).send('Error sending email');
                }
                res.send('Password reset link has been sent to your email. <a href="/" >Return to home</a>');
            });
        });
    });
});


app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    
    // Check if token is valid and not expired
    const sql = `SELECT * FROM users WHERE reset_token = ? AND reset_token_expiration > ?`;
    db.get(sql, [token, Date.now()], (err, user) => {
        if (err || !user) {
            return res.status(400).send('Invalid or expired token');
        }

        // Render password reset form
        res.render('reset-password', { token, error: null });
    });
});

app.post('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    // Check if token is valid and not expired
    const sql = `SELECT * FROM users WHERE reset_token = ? AND reset_token_expiration > ?`;
    db.get(sql, [token, Date.now()], (err, user) => {
        if (err || !user) {
            return res.status(400).send('Invalid or expired token');
        }

        // Hash the new password and update the database
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Error hashing password:', err.message);
                return res.status(500).send('Error resetting password');
            }

            const updateSql = `UPDATE users SET password = ?, reset_token = NULL, reset_token_expiration = NULL WHERE id = ?`;
            db.run(updateSql, [hashedPassword, user.id], (err) => {
                if (err) {
                    console.error('Error updating password:', err.message);
                    return res.status(500).send('Error updating password');
                }

                res.send('Your password has been reset successfully. You can now <a href="/login">log in</a>.');
            });
        });
    });
});


//Main Page
app.get('/', (req, res) => {
    const isLoggedIn = req.session.userId !== undefined;

    const totalBibleChapters = 1189; // Total chapters in the Bible

    // SQL query to get the total chapters read across all users
    const totalChaptersSql = `SELECT COUNT(*) as total FROM user_chapters`;

    // SQL query to get the number of times each chapter has been read
    const chapterReadsSql = `
        SELECT chapter_id, COUNT(chapter_id) AS times_read
        FROM user_chapters
        GROUP BY chapter_id`;

    // Fetch total chapters read across all users
    db.get(totalChaptersSql, (err, totalRow) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Error retrieving total chapters');
        }

        const totalChaptersRead = totalRow.total; // Total chapters read across all users

        // Fetch the number of times each chapter has been read
        db.all(chapterReadsSql, (err, rows) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send('Error retrieving chapter reads');
            }

            // Initialize an array to store the number of times each chapter has been read
            let timesReadArray = new Array(totalBibleChapters).fill(0);

            // Populate the timesReadArray with the number of reads for each chapter
            rows.forEach(row => {
                timesReadArray[row.chapter_id - 1] = row.times_read;  // Subtract 1 because array index starts from 0
            });

            // Find the minimum number of times any chapter has been read
            const minReads = Math.min(...timesReadArray);

            // Calculate how many complete sets of the Bible have been read
            const completions = minReads;

            // Calculate how many chapters have been read toward the next complete set
            const remainingChaptersForNextCompletion = timesReadArray.reduce((sum, reads) => sum + (reads > minReads ? 1 : 0), 0);

            // Progress toward the next complete set (in percentage)
            const progressPercentage = (remainingChaptersForNextCompletion / totalBibleChapters) * 100;

            if (!isLoggedIn) {
                return res.render('index', {
                    userName: null,
                    readerCounts: [],
                    chapterRows: [],
                    totalChaptersRead, // Total chapters read across all users
                    completions, // Number of full Bible completions
                    remainingChaptersForNextCompletion,
                    totalBibleChapters,
                    progressPercentage: progressPercentage.toFixed(2),
                    isLoggedIn: false
                });
            }

            const userId = req.session.userId;
            const userSql = `SELECT name FROM users WHERE id = ?`;
            const readersSql = `SELECT readers.reader_name, COUNT(user_chapters.id) as chapter_count
                                FROM readers
                                LEFT JOIN user_chapters ON readers.id = user_chapters.reader_id
                                WHERE readers.family_id = (SELECT family.id FROM family WHERE family.user_id = ?)
                                GROUP BY readers.reader_name`;
            const dataSql = `SELECT users.name as user_name, 
                                    readers.reader_name,
                                    family.family_name,
                                    chaptersmaster.book || ' ' || chaptersmaster.chapter as chapter_name,
                                    user_chapters.timestamp
                             FROM user_chapters
                             INNER JOIN users ON user_chapters.user_id = users.id
                             INNER JOIN readers ON user_chapters.reader_id = readers.id
                             INNER JOIN family ON readers.family_id = family.id
                             INNER JOIN chaptersmaster ON user_chapters.chapter_id = chaptersmaster.id
                             WHERE users.id = ?`;

            db.get(userSql, [userId], (err, userRow) => {
                if (err) {
                    console.error(err.message);
                    return res.status(500).send('Error retrieving user');
                }

                const userName = userRow ? userRow.name : 'Guest';

                db.all(readersSql, [userId], (err, readerCounts) => {
                    if (err) {
                        console.error(err.message);
                        return res.status(500).send('Error retrieving reader counts');
                    }

                    db.all(dataSql, [userId], (err, chapterRows) => {
                        if (err) {
                            console.error(err.message);
                            return res.status(500).send('Error retrieving chapters');
                        }

                        res.render('index', {
                            userName,
                            readerCounts,
                            chapterRows,
                            totalChaptersRead, // Total chapters read across all users
                            completions, // Number of full Bible completions
                            remainingChaptersForNextCompletion,
                            totalBibleChapters,
                            progressPercentage: progressPercentage.toFixed(2),
                            isLoggedIn: true
                        });
                    });
                });
            });
        });
    });
});




app.get('/unread-chapters', (req, res) => {
    const unreadChaptersSql = `
        SELECT chaptersmaster.book, chaptersmaster.chapter
        FROM chaptersmaster
        LEFT JOIN user_chapters ON chaptersmaster.id = user_chapters.chapter_id
        WHERE user_chapters.chapter_id IS NULL
        ORDER BY chaptersmaster.id 
    `;

    db.all(unreadChaptersSql, [], (err, unreadRows) => {
        if (err) {
            console.error('Error fetching unread chapters:', err.message);
            return res.status(500).send('Error retrieving unread chapters');
        }

        // Group unread chapters by book
        const unreadChaptersByBook = {};
        unreadRows.forEach(row => {
            const book = row.book.trim();
            if (!unreadChaptersByBook[book]) {
                unreadChaptersByBook[book] = [];
            }
            unreadChaptersByBook[book].push(row.chapter);
        });

        res.render('unread-chapters', { unreadChaptersByBook });
    });
});

app.get('/bible-progress', (req, res) => {
    const allChaptersSql = `
        SELECT chaptersmaster.id, chaptersmaster.book, chaptersmaster.chapter,
               CASE WHEN user_chapters.chapter_id IS NOT NULL THEN 1 ELSE 0 END as is_read
        FROM chaptersmaster
        LEFT JOIN user_chapters ON chaptersmaster.id = user_chapters.chapter_id
        ORDER BY chaptersmaster.id  -- Maintain Bible order
    `;

    db.all(allChaptersSql, [], (err, chapters) => {
        if (err) {
            console.error('Error fetching Bible chapters:', err.message);
            return res.status(500).send('Error retrieving Bible progress');
        }

        // Group chapters by book
        const chaptersByBook = {};
        chapters.forEach(row => {
            const book = row.book.trim();
            if (!chaptersByBook[book]) {
                chaptersByBook[book] = [];
            }
            chaptersByBook[book].push({
                chapter: row.chapter,
                isRead: row.is_read
            });
        });

        // Render only the progress view without the layout
        res.render('bible-progress', { chaptersByBook }, (err, html) => {
            if (err) {
                return res.status(500).send('Error rendering progress');
            }
            res.send(html); // Return the HTML fragment for the modal
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
                    chaptersByBook[book].push({ id: chapter.id, chapter: chapter.chapter });
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
        res.redirect('/');
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
