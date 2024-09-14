//Setup
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const path = require('path');
require('dotenv').config();
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const fs = require('fs');
const multer = require('multer');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const csvParser = require('csv-parser');
const { execSync } = require('child_process');
const flash = require('connect-flash');
const app = express();
const expressLayouts = require('express-ejs-layouts');
const port = 3000;

//app.* stuff
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(expressLayouts);
app.set('layout', 'layout');
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
app.use((req, res, next) => {
    res.locals.isLoggedIn = req.session && req.session.userId;
    res.locals.userName = req.session ? req.session.userName : '';
    next();
});
app.use((req, res, next) => {
    res.locals.role = req.session.role; // Make role available in all views
    next();
});
app.use((req, res, next) => {
    if (!req.session.userId) {
        return next();  // Skip if user is not logged in
    }

    const userId = req.session.userId;

    // Query to get family ID for the current user
    const familySql = `SELECT family.id as family_id
                       FROM family
                       WHERE family.user_id = ?`;

    db.get(familySql, [userId], (err, familyRow) => {
        if (err) {
            console.error('Error retrieving family:', err.message);
            return res.status(500).send('Error retrieving family');
        }

        if (!familyRow) {
            res.locals.totalPoints = 0;
            return next();
        }

        const familyId = familyRow.family_id;

        // Query to get total points for the user's family
        const pointsSql = `SELECT SUM(user_points) as total_points
                           FROM userpoints
                           JOIN readers ON userpoints.reader_id = readers.id
                           WHERE readers.family_id = ?`;

        db.get(pointsSql, [familyId], (err, pointsRow) => {
            if (err) {
                console.error('Error retrieving points:', err.message);
                res.locals.totalPoints = 0;  // Default to 0 points on error
                return next();
            }

            // Store the total points in res.locals, making it available in all views
            res.locals.totalPoints = pointsRow.total_points || 0;
            next();  // Continue to the next middleware/route
        });
    });
});
// Middleware to make the active reader available globally in views
app.use((req, res, next) => {
    // Check if the user is logged in and has an active reader selected
    if (req.session.userId && req.session.activeReaderId) {
        const readerSql = `
            SELECT readers.reader_name, COALESCE(SUM(userpoints.user_points), 0) as total_points
            FROM readers
            LEFT JOIN userpoints ON readers.id = userpoints.reader_id
            WHERE readers.id = ?
        `;

        db.get(readerSql, [req.session.activeReaderId], (err, reader) => {
            if (err) {
                console.error('Error retrieving active reader:', err.message);
                return next(); // Skip and continue to the next middleware or route
            }

            if (reader) {
                // Store reader information in res.locals to be available globally in views
                res.locals.activeReaderName = reader.reader_name;
                res.locals.activeReaderPoints = reader.total_points;
            }

            next(); // Continue to the next middleware or route
        });
    } else {
        // No active reader, just continue
        next();
    }
});

app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
// Setup session middleware (required for flash)
app.use(session({
    secret: process.env.FLASH_KEY,
    resave: false,
    saveUninitialized: true
}));

// Setup flash middleware
app.use(flash());

// Make flash messages available to all views
app.use((req, res, next) => {
    res.locals.successMessage = req.flash('success');
    res.locals.errorMessage = req.flash('error');
    next();
});
function ensureAdmin(req, res, next) {
    if (req.user && req.role === 'admin') {
        next(); // Proceed if the user is an admin
    } else {
        res.status(403).send('Forbidden: You do not have permission to access this page');
    }
}
// Connect to the SQLite database
let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the SQLite database.');
});

const { Pool } = require('pg');
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});


// Mail stuff for password change
const transporter = nodemailer.createTransport({
    host: 'smtp.zoho.com',
    port: 465, 
    secure: true, 
    auth: {
        user: process.env.ZOHO_USER, 
        pass: process.env.ZOHO_PASS 
    },
});
transporter.verify((error, success) => {
    if (error) {
        console.error('Error with transporter setup:', error);
    } else {
        console.log('Nodemailer is ready to send emails');
    }
});

// User Login/Register Routes
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});
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
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error(err.message);
                res.render('login', { error: 'An error occurred, please try again.' });
                return;
            }

            if (isMatch) {
                req.session.userId = user.id;
                req.session.userName = user.name;
                req.session.role = user.role;
                res.redirect('/select-reader');
            } else {
                res.render('login', { error: 'Invalid email or password.' });
            }
        });
    });
});
app.get('/select-reader', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    // Fetch the readers for the logged-in user's family
    const familySql = `SELECT readers.id, readers.reader_name 
                       FROM readers 
                       INNER JOIN family ON readers.family_id = family.id 
                       WHERE family.user_id = ?`;

    db.all(familySql, [req.session.userId], (err, readers) => {
        if (err) {
            console.error('Error retrieving readers:', err.message);
            return res.status(500).send('Error retrieving readers.');
        }

        if (readers.length === 0) {
            return res.redirect('/create-family'); // Redirect if no readers exist
        }

        // Render the select reader page
        res.render('select-reader', { readers });
    });
});
app.get('/reader-profile', (req, res) => {
    const readerId = req.session.activeReaderId;

    if (!readerId) {
        return res.redirect('/select-reader');
    }

    // Fetch reader's points and current level
    const readerSql = `
        SELECT readers.reader_name, COALESCE(SUM(userpoints.user_points), 0) as total_points, levels.level_name, levels.min_points
        FROM readers
        LEFT JOIN userpoints ON readers.id = userpoints.reader_id
        LEFT JOIN levels ON readers.current_level_id = levels.id
        WHERE readers.id = ?
    `;

    db.get(readerSql, [readerId], (err, readerData) => {
        if (err || !readerData) {
            console.error("Error fetching reader data:", err.message);
            return res.status(500).send('Error retrieving reader profile');
        }

        const totalPoints = readerData.total_points;
        const currentLevelName = readerData.level_name;
        const currentMinPoints = readerData.min_points;

        // Fetch the next level info
        const nextLevelSql = `SELECT level_name, min_points FROM levels WHERE min_points > ? ORDER BY min_points ASC LIMIT 1`;
        db.get(nextLevelSql, [totalPoints], (err, nextLevel) => {
            let nextLevelPoints = nextLevel ? nextLevel.min_points : currentMinPoints;  // If no next level, keep current
            let progressPercentage = Math.min((totalPoints - currentMinPoints) / (nextLevelPoints - currentMinPoints) * 100, 100);

            res.render('reader-profile', {
                readerName: readerData.reader_name,
                readerTotalPoints: totalPoints,
                level: currentLevelName,
                progressPercentage: Math.round(progressPercentage),
                nextLevelPoints,
                currentMinPoints
            });
        });
    });
});
app.get('/reader-progress', (req, res) => {
    const activeReaderId = req.session.activeReaderId; // Assuming active reader ID is stored in the session

    const allChaptersSql = `
        SELECT chaptersmaster.id, chaptersmaster.book, chaptersmaster.chapter,
               CASE WHEN MAX(user_chapters.chapter_id) IS NOT NULL THEN 1 ELSE 0 END as is_read
        FROM chaptersmaster
        LEFT JOIN user_chapters ON chaptersmaster.id = user_chapters.chapter_id
                               AND user_chapters.reader_id = ?  -- Filter by the active reader
        GROUP BY chaptersmaster.id, chaptersmaster.book, chaptersmaster.chapter
        ORDER BY chaptersmaster.id  -- Maintain Bible order
    `;

    db.all(allChaptersSql, [activeReaderId], (err, chapters) => {
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
        
        const readerNameSql = `SELECT reader_name FROM readers WHERE id = ?`;
        db.get(readerNameSql, activeReaderId, (err, reader) => {
            // Render only the progress view without the layout
            res.render('reader-progress', { chaptersByBook, readerName: reader.reader_name }, (err, html) => {
                res.send(html); // Return the HTML fragment for the modal
            });
        });
        
    });
});
app.post('/set-active-reader', (req, res) => {
    const readerId = req.body.readerId;

    if (!readerId) {
        return res.status(400).send('Please select a reader.');
    }

    // Set the active reader in the session
    req.session.activeReaderId = readerId;

    // Redirect to the dashboard or the homepage
    res.redirect('/');
});
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Error logging out.');
        }
        res.redirect('/');
    });
});
app.post('/register', (req, res) => {
    const { name, email, password } = req.body;
    const checkEmailSql = `SELECT * FROM users WHERE email = ?`;
    db.get(checkEmailSql, [email], (err, row) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Error checking email');
        }
        if (row) {
            return res.render('login', { error: 'Email already in use. Please log in.' });
        }
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
                res.redirect('/manage');
            });
        });
    });
});
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
            const resetLink = `https://refreadapp-cada9a524b5a.herokuapp.com/reset-password/${token}`;

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
app.get('/bible-progress', (req, res) => {
    const allChaptersSql = `
        SELECT chaptersmaster.id, chaptersmaster.book, chaptersmaster.chapter,
               CASE WHEN MAX(user_chapters.chapter_id) IS NOT NULL THEN 1 ELSE 0 END as is_read
        FROM chaptersmaster
        LEFT JOIN user_chapters ON chaptersmaster.id = user_chapters.chapter_id
        GROUP BY chaptersmaster.id, chaptersmaster.book, chaptersmaster.chapter
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
    let pointsToAdd = 0;  // Track the total points to add

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
                pointsToAdd++;
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

            if (pointsToAdd > 0) {
                // Call addPoints once with the total points to add
                addPoints(readerId, pointsToAdd);
            }

            console.log('Chapters successfully recorded.');
            // Flash a success message
            req.flash('success', `Thank you for reporting chapters!`);
            res.redirect('/reader-profile');
        });
    }
});
app.get('/record-by-book', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const familySql = `SELECT family.id FROM family WHERE user_id = ?`;
    const readersSql = `SELECT readers.id, readers.reader_name 
                        FROM readers 
                        INNER JOIN family ON readers.family_id = family.id
                        WHERE family.user_id = ?`;
    
    // Fetch distinct books without sorting alphabetically, using the natural order in the database
    const booksSql = `SELECT DISTINCT book FROM chaptersmaster ORDER BY id`;

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

            // Fetch all books in the order they appear in the chaptersmaster table
            db.all(booksSql, [], (err, books) => {
                if (err) {
                    console.error('Error retrieving books:', err.message);
                    return res.status(500).send('Error retrieving books');
                }

                // Render the record-by-book page with readers and books
                res.render('record-by-book', { userName: req.session.userName, readers, books });
            });
        });
    });
});
app.post('/record-by-book', (req, res) => {
    const userId = req.session.userId; // Assuming userId is stored in the session
    const readerId = req.body.readerId;
    let bookNames = req.body['bookName[]'];

    // Check if bookNames is not an array (if only one book is selected)
    if (!Array.isArray(bookNames)) {
        bookNames = [bookNames];  // Convert single string to an array
    }

    console.log('readerId:', readerId);
    console.log('bookNames:', bookNames);
    console.log('bookNames length:', bookNames.length);

    if (!readerId || !bookNames || bookNames.length === 0) {
        return res.status(400).send('Missing required data.');
    }

    const insertChapterSql = `INSERT INTO user_chapters (user_id, reader_id, chapter_id) VALUES (?, ?, ?)`;
    const addPointsSql = `INSERT INTO userpoints (reader_id, user_points) VALUES (?, ?)`;
    
    const stmt = db.prepare(insertChapterSql); // Prepare the statement for inserting chapters

    let totalPointsToAdd = 0;
    let pendingOperations = 0;
    let hasErrorOccurred = false;

    // Iterate over the bookNames array
    bookNames.forEach(bookName => {
        console.log('Processing book:', bookName);
        
        // Fetch all chapters for the book
        db.all(`SELECT id, chapter FROM chaptersmaster WHERE book = ?`, [bookName], (err, chapters) => {
            if (err) {
                console.error(`Error retrieving chapters for ${bookName}:`, err.message);
                hasErrorOccurred = true;
                return;
            }

            pendingOperations += chapters.length;

            // Insert each chapter into the user_chapters table
            chapters.forEach(chapter => {
                stmt.run([userId, readerId, chapter.id], (err) => {
                    if (err) {
                        console.error(`Error inserting chapter ${chapter.chapter} for ${bookName}:`, err.message);
                        hasErrorOccurred = true;
                    } else {
                        totalPointsToAdd++; // Increment points for each chapter successfully added
                    }

                    pendingOperations--;

                    if (pendingOperations === 0) {
                        finalizeTransaction();
                    }
                });
            });
        });
    });

    function finalizeTransaction() {
        stmt.finalize((err) => {
            if (err) {
                console.error('Error finalizing chapter insert statement:', err.message);
                return res.status(500).send('Error recording chapters.');
            }

            if (hasErrorOccurred) {
                console.log('Some errors occurred during the process.');
                return res.status(500).send('Error occurred while recording some chapters.');
            }

            if (totalPointsToAdd > 0) {
                // Add the total points to the userpoints table
                addPoints(readerId, totalPointsToAdd);
                console.log(`${totalPointsToAdd} points added for readerId: ${readerId}`);
                req.flash('success', `Thank you for reporting chapters!`);
                res.redirect('/reader-profile');

            } else {
                res.redirect('/reader-profile');
            }
        });
    }
});
app.get('/manage', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const activeReader = req.session.activeReaderId || null;
    const userId = req.session.userId;
    const userRole = req.session.role;

    // Fetch the logged-in user's name and family_id
    const userSql = `SELECT name, family_id FROM users WHERE id = ?`;

    db.get(userSql, [userId], (err, userRow) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Error retrieving user');
        }

        const userName = userRow ? userRow.name : 'Guest';
        const familyId = userRow ? userRow.family_id : null;
        const context = { userName, isAdmin: false, activeReader }; // Context to pass to the view

        // If the user is an admin, fetch all users' chapters
        if (userRole === 'admin') {
            const allUsersChaptersSql = `
                SELECT family.family_name, 
                       readers.reader_name,
                       COUNT(user_chapters.id) as total_chapters_read
                FROM user_chapters
                INNER JOIN readers ON user_chapters.reader_id = readers.id
                INNER JOIN family ON readers.family_id = family.id
                GROUP BY readers.reader_name, family.family_name
                ORDER BY total_chapters_read DESC
            `;

            db.all(allUsersChaptersSql, [], (err, chapters) => {
                if (err) {
                    console.error(err.message);
                    return res.status(500).send('Error retrieving chapters for all users');
                }
                context.chapters = chapters;
                context.isAdmin = true;

                // Fetch the family group for the logged-in user
                fetchFamilyGroup(familyId, context, res);
            });
        } else {
            // For non-admin users, directly fetch the family group
            fetchFamilyGroup(familyId, context, res);
        }
    });
});

function fetchFamilyGroup(familyId, context, res) {
    if (!familyId) {
        // If the user doesn't have a family_id, prompt them to create a family
        context.family = null;
        context.readers = [];
        return res.render('manage', context); // Render the view with step 1 (create family)
    }

    const familySql = `
        SELECT family.id as family_id, family.family_name, family.join_token, readers.id as reader_id, readers.reader_name,
               COALESCE(SUM(userpoints.user_points), 0) as total_points  -- Calculate points for each reader
        FROM family
        LEFT JOIN readers ON family.id = readers.family_id
        LEFT JOIN userpoints ON readers.id = userpoints.reader_id
        WHERE family.id = ?
        GROUP BY readers.id
    `;

    db.all(familySql, [familyId], (err, rows) => {
        if (err) {
            console.error('Error retrieving family group:', err.message);
            return res.status(500).send('Error retrieving family group');
        }

        // If no readers exist for the family, show Step 2: Add a Reader
        const family = rows.length > 0 ? rows[0] : null;

        const readers = rows.filter(row => row.reader_id).map(row => ({
            id: row.reader_id,
            name: row.reader_name,
            points: row.total_points   // Include the points for each reader
        }));

        if (!family) {
            context.family = null;
            context.readers = [];
            return res.render('manage', context); // Render the view with step 1 (create family)
        }

        if (readers.length === 0) {
            context.family = family;
            context.readers = [];
            return res.render('manage', context); // Render the view with step 2 (add a reader)
        }

        // If both family and readers exist, display the table of readers
        context.family = family;
        context.readers = readers;
        context.activeReader = context.activeReader || null;
        context.joinToken = family.join_token; 
        res.render('manage', context);
    });
}

app.post('/addReader', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const { familyId, readerName } = req.body;

    // Insert a new reader associated with the logged-in user's family
    const insertReaderSql = `INSERT INTO readers (family_id, reader_name) VALUES (?, ?)`;
    const findNewReaderSql = `SELECT id FROM readers WHERE family_id = ? AND reader_name = ?`;
    db.run(insertReaderSql, [familyId, readerName], function (err) {
        if (err) {
            console.error('Error adding reader:', err.message);
            return res.status(500).send('Error adding reader');
        }
        console.log(`Added new reader with ID ${this.lastID}`);
        db.get(findNewReaderSql, [familyId, readerName],(err, row) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send('Error retrieving reader id');
            }
            const readerId = row.id;
            addPoints(readerId, 50);
        });
        res.redirect('/manage');
    });
});
app.post('/createFamily', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const { familyName } = req.body;
    const token = crypto.randomBytes(20).toString('hex');

    // Insert a new family for the logged-in user
    const createFamilySql = `INSERT INTO family (user_id, family_name, join_token) VALUES (?, ?, ?)`;

    db.run(createFamilySql, [userId, familyName, token], function (err) {
        if (err) {
            console.error('Error creating family:', err.message);
            return res.status(500).send('Error creating family');
        }
        
        // Retrieve the family ID of the newly created family
        const familyId = this.lastID;
        console.log(`Created new family with ID ${familyId}`);

        // Update the user's family_id in the users table
        const updateUserFamilySql = `UPDATE users SET family_id = ? WHERE id = ?`;
        db.run(updateUserFamilySql, [familyId, userId], function (err) {
            if (err) {
                console.error('Error updating user:', err.message);
                return res.status(500).send('Error updating user');
            }

            // After updating the user, redirect to the manage page
            res.redirect('/manage');
        });
    });
});

app.post('/joinFamily', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const { familyToken } = req.body;
    const joinFamilySql = `SELECT * FROM family WHERE join_token = ?`;

    db.get(joinFamilySql, [familyToken], (err, row) => {
        if (err) {
            console.error('Error joining family:', err.message);
            return res.status(500).send('Error joining family');
        }

        if (!row) {
            // Handle the case where no family was found with the provided token
            console.log('No family found with that token');
            return res.status(404).send('Family not found');
        }

        const familyId = row.id;
        console.log(`Found family with ID ${familyId}`);

        db.run('UPDATE users SET family_id = ? WHERE id = ?', [familyId, userId], (updateErr) => {
            if (updateErr) {
                console.error('Error updating user with family ID:', updateErr.message);
                return res.status(500).send('Error joining family');
            }

            // Redirect to manage page after successful update
            res.redirect('/manage');
        });
    });
});

app.get('/edit-reader/:readerId', (req, res) => {
    const readerId = req.params.readerId;

    const readerSql = `SELECT reader_name FROM readers WHERE id = ?`;
    db.get(readerSql, [readerId], (err, reader) => {
        if (err) {
            console.error('Error fetching reader:', err.message);
            return res.status(500).send('Error fetching reader');
        }

        if (!reader) {
            return res.status(404).send('Reader not found');
        }

        res.render('edit-reader', { readerId, readerName: reader.reader_name });
    });
});
app.post('/edit-reader/:readerId', (req, res) => {
    const readerId = req.params.readerId;
    const newName = req.body.readerName;

    const updateReaderSql = `UPDATE readers SET reader_name = ? WHERE id = ?`;
    db.run(updateReaderSql, [newName, readerId], function (err) {
        if (err) {
            console.error('Error updating reader:', err.message);
            return res.status(500).send('Error updating reader');
        }

        // Redirect back to the manage page after updating the reader
        res.redirect('/manage');
    });
});
app.post('/delete-reader/:readerId', (req, res) => {
    const readerId = req.params.readerId;

    // Step 1: Delete all related chapters for this reader
    const deleteChaptersSql = `DELETE FROM user_chapters WHERE reader_id = ?`;
    db.run(deleteChaptersSql, [readerId], function(err) {
        if (err) {
            console.error('Error deleting chapters:', err.message);
            return res.status(500).send('Error deleting chapters');
        }

        console.log(`Chapters for reader ID: ${readerId} deleted successfully.`);

        // Step 2: Delete the reader after chapters are deleted
        const deleteReaderSql = `DELETE FROM readers WHERE id = ?`;
        db.run(deleteReaderSql, [readerId], function(err) {
            if (err) {
                console.error('Error deleting reader:', err.message);
                return res.status(500).send('Error deleting reader');
            }

            console.log(`Reader with ID: ${readerId} deleted successfully.`);
            res.redirect('/manage');
        });
    });
});
app.get('/admin', (req, res, next) => {
    if (req.session.role !== 'admin') {
        return res.redirect('/');
    } 
    db.all('SELECT name, email, role FROM users', [],(err, users) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Server Error');
        }
        res.render('admin', { users });
    });
    
});

//Static Pages
app.get('/about', (req, res) => {
    res.render('about');
});

//Not in use at the moment
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

//Administration stuff
app.post('/clear-chapters', (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).send('Forbidden'); // Only allow admins
    }

    runScriptSync('makeUserChapters.js');
    console.log('All scripts have been executed.');
});
app.post('/clear-points', (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).send('Forbidden'); // Only allow admins
    }

    runScriptSync('clearUserPoints.js');
    console.log('All scripts have been executed.');
});
function runScriptSync(scriptName) {
    try {
        console.log(`Running ${scriptName}...`);
        const output = execSync(`node ${scriptName}`, { stdio: 'inherit' });
        console.log(`Finished running ${scriptName}`);
    } catch (error) {
        console.error(`Error executing ${scriptName}:`, error.message);
    }
}
app.get('/export-chapters-csv', (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).send('Unauthorized');
    }

    const sql = `SELECT * FROM user_chapters`;

    db.all(sql, [], (err, rows) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Error retrieving user chapters');
        }

        // Get current timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

        // Define the filename with the timestamp and set a directory path for saving
        const filename = `user_chapters_${timestamp}.csv`;
        const filePath = path.join(__dirname, 'backups', filename); // Store in an "exports" directory

        // Define the CSV writer
        const csvWriter = createCsvWriter({
            path: filePath,
            header: [
                { id: 'id', title: 'id' },
                { id: 'user_id', title: 'user_id' },
                { id: 'reader_id', title: 'reader_id' },
                { id: 'chapter_id', title: 'chapter_id' },
                { id: 'timestamp', title: 'timestamp' }
            ]
        });

        // Write CSV file to the server
        csvWriter.writeRecords(rows)
            .then(() => {
                console.log(`CSV file written successfully to ${filePath}`);
                // Send JSON response to trigger alert on the client
                res.json({ success: true, message: `CSV file saved at ${filePath}` });
            })
            .catch(err => {
                console.error('Error writing CSV file:', err.message);
                res.status(500).json({ success: false, message: 'Error writing CSV file' });
            });
    });
});
const upload = multer({
    dest: 'uploads/' // This directory will store uploaded files temporarily
});
app.post('/upload-user-chapters', upload.single('csvFile'), (req, res) => {
    if (!req.session.userId || req.session.role !== 'admin') {
        return res.status(403).send('Unauthorized');
    }

    const filePath = path.join(__dirname, req.file.path);

    // Initialize an empty array to store parsed CSV data
    const csvData = [];

    // Read the CSV file and parse its contents
    fs.createReadStream(filePath)
        .pipe(csvParser())
        .on('data', (row) => {
            csvData.push(row); // Push each row of data to the array
        })
        .on('end', () => {
            console.log('CSV file successfully processed:', csvData);

            // Insert CSV data back into the user_chapters table
            const insertSql = `INSERT INTO user_chapters (user_id, reader_id, chapter_id, timestamp) VALUES (?, ?, ?, ?)`;
            const stmt = db.prepare(insertSql);

            csvData.forEach((row) => {
                stmt.run([row.user_id, row.reader_id, row.chapter_id, row.timestamp], (err) => {
                    if (err) {
                        console.error('Error inserting row into user_chapters:', err.message);
                    }
                });
            });

            stmt.finalize((err) => {
                if (err) {
                    console.error('Error finalizing statement:', err.message);
                    return res.status(500).send('Error restoring data');
                }

                // Clean up the uploaded file
                fs.unlink(filePath, (err) => {
                    if (err) {
                        console.error('Error deleting uploaded file:', err.message);
                    }
                });

                // Send a success response
                res.send('CSV file successfully uploaded and user chapters restored.');
            });
        });
});

//Gamification Components
function addPoints(readerId, pointsToAdd) {
    // First, check if the user already has an entry in the userpoints table
    const checkSql = `SELECT user_points FROM userpoints WHERE reader_id = ?`;

    db.get(checkSql, [readerId], (err, row) => {
        if (err) {
            console.error("Error checking for existing points:", err.message);
            return;
        }

        if (row) {
            // If the user already has points, calculate the new total points
            const newPoints = row.user_points + pointsToAdd;
            const updateSql = `UPDATE userpoints SET user_points = ? WHERE reader_id = ?`;
            console.log(`New total points: ${newPoints}`);
            db.run(updateSql, [newPoints, readerId], (err) => {
                if (err) {
                    console.error("Error updating points:", err.message);
                } else {
                    console.log(`Updated points for reader ${readerId}. New total: ${newPoints}`);
                    updateReaderLevel(readerId, newPoints);
                }
            });
        } else {
            // If the user doesn't have any points yet, insert a new row
            const insertSql = `INSERT INTO userpoints (reader_id, user_points) VALUES (?, ?)`;

            db.run(insertSql, [readerId, pointsToAdd], (err) => {
                if (err) {
                    console.error("Error inserting new points:", err.message);
                } else {
                    console.log(`Inserted ${pointsToAdd} points for reader ${readerId}.`);
                    updateReaderLevel(readerId, pointsToAdd);
                }
            });
        }
    });
}
function updateReaderLevel(readerId, totalPoints) {
    // Fetch the level that corresponds to the reader's total points
    const levelSql = `SELECT id, level_name FROM levels WHERE min_points <= ? ORDER BY min_points DESC LIMIT 1`;

    db.get(levelSql, [totalPoints], (err, level) => {
        if (err) {
            console.error('Error fetching level:', err.message);
        } else if (level) {
            // Update the reader's level in the readers table
            const updateLevelSql = `UPDATE readers SET current_level_id = ? WHERE id = ?`;
            db.run(updateLevelSql, [level.id, readerId], (err) => {
                if (err) {
                    console.error('Error updating reader level:', err.message);
                } else {
                    console.log(`Updated reader ${readerId} to level: ${level.level_name}`);
                }
            });
        }
    });
}
app.get('/leaderboard', (req, res) => {
    // Query to get the top 10 readers by points
    console.log('Leaderboard route accessed');
    const leaderboardSql = `
        SELECT readers.reader_name, SUM(userpoints.user_points) as total_points
        FROM userpoints
        JOIN readers ON userpoints.reader_id = readers.id
        GROUP BY readers.reader_name
        ORDER BY total_points DESC
        LIMIT 10
    `;

    db.all(leaderboardSql, [], (err, rows) => {
        if (err) {
            console.error('Error retrieving leaderboard:', err.message);
            return res.status(500).send('Error retrieving leaderboard');
        }

        // Pass the leaderboard data to the view
        res.render('leaderboard', { leaderboard: rows });
    });
});
app.get('/reader-reports/:readerId', (req, res) => {
    const readerId = req.params.readerId;

    // Query to get all chapters reported by this reader
    const reportsSql = `
        SELECT user_chapters.chapter_id, chaptersmaster.book, chaptersmaster.chapter, user_chapters.timestamp
        FROM user_chapters
        JOIN chaptersmaster ON user_chapters.chapter_id = chaptersmaster.id
        WHERE user_chapters.reader_id = ?
        ORDER BY user_chapters.timestamp DESC, chaptersmaster.chapter ASC
    `;

    db.all(reportsSql, [readerId], (err, reports) => {
        if (err) {
            console.error('Error retrieving reports:', err.message);
            return res.status(500).send('Error retrieving reports');
        }

        // Pass the reports data to the view
        res.render('reader-reports', { reports });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
