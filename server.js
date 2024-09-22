// Setup
import axios from 'axios';
import express from 'express';
import sqlite3 from 'sqlite3';
import session from 'express-session';
import connectSqlite3 from 'connect-sqlite3';
import bcrypt from 'bcrypt';
import path from 'path';
import dotenv from 'dotenv';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import fs from 'fs';
import multer from 'multer';
import { createObjectCsvWriter as createCsvWriter } from 'csv-writer';
import csvParser from 'csv-parser';
import { execSync } from 'child_process';
import flash from 'connect-flash';
import expressLayouts from 'express-ejs-layouts';
import OpenAI from "openai";

// SQLite3 needs to be verbose
sqlite3.verbose();

// Set up SQLite store for session
const SQLiteStore = connectSqlite3(session);

// Configure dotenv to load environment variables
dotenv.config();

// Initialize OpenAI API
// Configure OpenAI API with key
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });


// Initialize Express app
const app = express();

import { fileURLToPath } from 'url';
import { dirname } from 'path';

// Recreate __dirname in ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);



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
    if (req.session.activeReaderLevelId) {
        res.locals.activeReaderLevelId = req.session.activeReaderLevelId;
    } else {
        res.locals.activeReaderLevelId = 1; // Default value if not set
    }
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
    const familySql = `SELECT family_id FROM users WHERE id = ?`;

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
app.use(session({
    secret: process.env.FLASH_KEY,
    resave: false,
    saveUninitialized: true
}));
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
let db = new sqlite3.Database('../mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the SQLite database.');
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
app.get('/quiz', (req, res) => {
    res.render('quiz', { error: null });
});
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
            return res.redirect('/manage'); // Redirect if no readers exist
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

    // Fetch reader's points, current level, level_id, and description
    const readerSql = `
        SELECT readers.reader_name, COALESCE(SUM(userpoints.user_points), 0) as total_points, 
               levels.level_name, levels.min_points, levels.id as level_id, levels.description, 
               readers.referral_token
        FROM readers
        LEFT JOIN userpoints ON readers.id = userpoints.reader_id
        LEFT JOIN levels ON readers.current_level_id = levels.id
        WHERE readers.id = ?
    `;

    db.get(readerSql, [readerId], (err, readerData) => {
        if (err || !readerData) {
            console.error("Error fetching reader data:", err ? err.message : 'No reader data');
            return res.status(500).send('Error retrieving reader profile');
        }

        const totalPoints = readerData.total_points;
        const currentLevelName = readerData.level_name;
        const currentMinPoints = readerData.min_points;
        const currentLevelId = readerData.level_id; // Get the level_id
        const levelDescription = readerData.description; // Get the level description
        let referralToken = readerData.referral_token;

        // If no referral token exists, generate one
        if (!referralToken) {
            referralToken = crypto.randomBytes(16).toString('hex');
            db.run('UPDATE readers SET referral_token = ? WHERE id = ?', [referralToken, readerId], (err) => {
                if (err) {
                    console.error('Error generating referral token:', err.message);
                }
            });
        }

        // Fetch the next level info
        const nextLevelSql = `SELECT level_name, min_points FROM levels WHERE min_points > ? ORDER BY min_points ASC LIMIT 1`;
        db.get(nextLevelSql, [totalPoints], (err, nextLevel) => {
            let nextLevelPoints = nextLevel ? nextLevel.min_points : currentMinPoints;  // If no next level, keep current
            let progressPercentage = Math.min((totalPoints - currentMinPoints) / (nextLevelPoints - currentMinPoints) * 100, 100);

            // Pass all necessary data to the view
            res.render('reader-profile', {
                readerName: readerData.reader_name,
                readerTotalPoints: totalPoints,
                level: currentLevelName,
                progressPercentage: Math.round(progressPercentage),
                nextLevelPoints,
                currentMinPoints,
                currentLevelId, // Pass level_id to the view for dynamic image selection
                levelDescription, // Pass the level description to the view
                referralToken,  // Use the referralToken variable
                protocol: req.protocol,
                host: req.get('host')
            });
        });
    });
});
app.get('/reader-progress', (req, res) => {
    const activeReaderId = req.session.activeReaderId; // Assuming active reader ID is stored in the session
    const totalBibleChapters = 1189; // Total chapters in the Bible

    // SQL query to get the number of times each chapter has been read by the active reader
    const chapterReadsSql = `
        SELECT chapter_id, COUNT(chapter_id) AS times_read
        FROM user_chapters
        WHERE reader_id = ?
        GROUP BY chapter_id
    `;

    db.all(chapterReadsSql, [activeReaderId], (err, rows) => {
        if (err) {
            console.error('Error fetching reader-specific chapters:', err.message);
            return res.status(500).send('Error retrieving Bible progress');
        }

        // Initialize an array to store the number of times each chapter has been read
        let timesReadArray = new Array(totalBibleChapters).fill(0);

        // Populate the timesReadArray with the number of reads for each chapter
        rows.forEach(row => {
            timesReadArray[row.chapter_id - 1] = row.times_read;  // Subtract 1 because array index starts from 0
        });

        // Find the minimum number of times any chapter has been read (i.e., full Bible completions for this reader)
        const minReads = Math.min(...timesReadArray);

        // Calculate how many chapters have been read toward the next full Bible completion for this reader
        const remainingChaptersForNextCompletion = timesReadArray.reduce((sum, reads) => sum + (reads > minReads ? 1 : 0), 0);

        // Fetch chapters for the current cycle, filtering by active reader and taking into account minReads
        const allChaptersSql = `
            SELECT chaptersmaster.id, chaptersmaster.book, chaptersmaster.chapter,
                   CASE WHEN COUNT(user_chapters.chapter_id) > ? THEN 1 ELSE 0 END as is_read
            FROM chaptersmaster
            LEFT JOIN user_chapters ON chaptersmaster.id = user_chapters.chapter_id
                                   AND user_chapters.reader_id = ?  -- Filter by the active reader
            GROUP BY chaptersmaster.id, chaptersmaster.book, chaptersmaster.chapter
            ORDER BY chaptersmaster.id  -- Maintain Bible order
        `;

        db.all(allChaptersSql, [minReads, activeReaderId], (err, chapters) => {
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

            // Fetch the active reader's name
            const readerNameSql = `SELECT reader_name FROM readers WHERE id = ?`;
            db.get(readerNameSql, [activeReaderId], (err, reader) => {
                if (err) {
                    console.error('Error retrieving reader name:', err.message);
                    return res.status(500).send('Error retrieving reader name');
                }

                // Render the reader progress view
                res.render('reader-progress', { chaptersByBook, readerName: reader.reader_name }, (err, html) => {
                    if (err) {
                        return res.status(500).send('Error rendering progress');
                    }
                    res.send(html); // Return the HTML fragment for the modal
                });
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

    const getReaderLevelSql = `SELECT readers.current_level_id FROM readers WHERE id = ?`;
    db.get(getReaderLevelSql, [readerId], (err, row) => {
        if (err) {
            console.error('Error fetching reader level:', err.message);
            return res.status(500).send('Error retrieving reader level');
        }

        if (row && row.current_level_id) {
            req.session.activeReaderLevelId = row.current_level_id; // Correctly set the current_level_id
        } else {
            req.session.activeReaderLevelId = 1; // Default to 1 if no level is found
        }

        // Redirect to the dashboard or the homepage
        res.redirect('/reader-profile');
    });
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
app.get('/register', (req, res) => {
    const referralToken = req.query.ref;  // Extract the referral token from the query parameter

    if (referralToken) {
        // Check if the referral token exists
        const findReaderSql = `SELECT id FROM readers WHERE referral_token = ?`;
        db.get(findReaderSql, [referralToken], (err, reader) => {
            if (err || !reader) {
                console.error('Invalid referral token:', err ? err.message : 'No reader found');
                req.flash('error', 'Invalid referral link.');
                return res.redirect('/login');
            }

            // Save the referral ID in session or pass it to the registration form
            req.session.referringReaderId = reader.id;

            // Proceed to registration page, passing referral information
            res.render('register', { referralReader: reader.id });  // Pass the referral reader id to the form if needed
        });
    } else {
        // No referral token, just render the registration form as usual
        res.render('register', { referralReader: null });
    }
});
app.post('/register', (req, res) => {
    const { name, email, password } = req.body;
    const referringReaderId = req.session.referringReaderId;  // Get the referring reader id from session

    const checkEmailSql = `SELECT * FROM users WHERE email = ?`;
    db.get(checkEmailSql, [email], (err, row) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Error checking email');
        }

        if (row) {
            return res.render('login', { error: 'Email already in use. Please log in.' });
        }

        // Hash the password before storing it
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send('Error hashing password');
            }

            // Insert the new user into the database
            const insertUserSql = `INSERT INTO users (name, email, password, referrer_id) VALUES (?, ?, ?, ?)`;
            db.run(insertUserSql, [name, email, hashedPassword, referringReaderId], function (err) {
                if (err) {
                    console.error(err.message);
                    return res.status(500).send('Error registering user');
                }

                const userId = this.lastID;

                // Automatically log the user in after registration
                req.session.userId = userId;
                req.session.userName = name;

                // Check if there is a referring reader
                if (referringReaderId) {
                    const addPointsSql = `INSERT INTO userpoints (reader_id, user_points) VALUES (?, ?)`;
                    db.run(addPointsSql, [referringReaderId, 25], (err) => {
                        if (err) {
                            console.error('Error adding referral points:', err.message);
                        } else {
                            // Add flash message for the referring reader
                            req.session.flashMessage = 'You have earned 25 points from a referral!';
                        }
                    });
                }

                // Redirect to the manage page after successful registration
                res.redirect('/manage');
            });
        });
    });
});
app.get('/referrals', (req, res) => {
    const readerId = req.session.activeReaderId;

    if (!readerId) {
        return res.redirect('/select-reader');
    }

    // Query to find all users referred by the reader
    const referralSql = `SELECT name, email FROM users WHERE referrer_id = ?`;
    db.all(referralSql, [readerId], (err, referrals) => {
        if (err) {
            console.error("Error fetching referrals:", err.message);
            return res.status(500).send('Error retrieving referral data');
        }
        db.get(`SELECT reader_name FROM readers WHERE id = ?`, [readerId], (err, reader) => {
            const readerName = reader.reader_name;
            res.render('referrals', {
                readerName,
                referrals
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
            const resetLink = `http://app.reformationmonth.com/reset-password/${token}`;

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
app.post('/leave-family', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login'); // Redirect if not logged in
    }

    const userId = req.session.userId;

    // SQL to remove the family_id from the user's row
    const leaveFamilySql = `UPDATE users SET family_id = NULL WHERE id = ?`;

    db.run(leaveFamilySql, [userId], function (err) {
        if (err) {
            console.error('Error leaving family:', err.message);
            return res.status(500).send('Error leaving family');
        }

        // Redirect to /manage after successful family removal
        res.redirect('/manage');
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
    const totalBibleChapters = 1189; // Total chapters in the Bible

    // SQL query to get the number of times each chapter has been read
    const chapterReadsSql = `
        SELECT chapter_id, COUNT(chapter_id) AS times_read
        FROM user_chapters
        GROUP BY chapter_id`;

    db.all(chapterReadsSql, (err, rows) => {
        if (err) {
            console.error('Error fetching Bible chapters:', err.message);
            return res.status(500).send('Error retrieving Bible progress');
        }

        // Initialize an array to store the number of times each chapter has been read
        let timesReadArray = new Array(totalBibleChapters).fill(0);

        // Populate the timesReadArray with the number of reads for each chapter
        rows.forEach(row => {
            timesReadArray[row.chapter_id - 1] = row.times_read;  // Subtract 1 because array index starts from 0
        });

        // Find the minimum number of times any chapter has been read (i.e., full Bible completions)
        const minReads = Math.min(...timesReadArray);

        // Calculate how many chapters have been read toward the next full Bible
        const remainingChaptersForNextCompletion = timesReadArray.reduce((sum, reads) => sum + (reads > minReads ? 1 : 0), 0);

        // Group chapters by book and indicate whether they've been read for the current completion cycle
        const allChaptersSql = `
            SELECT chaptersmaster.id, chaptersmaster.book, chaptersmaster.chapter,
                   CASE WHEN COUNT(user_chapters.chapter_id) > ? THEN 1 ELSE 0 END as is_read
            FROM chaptersmaster
            LEFT JOIN user_chapters ON chaptersmaster.id = user_chapters.chapter_id
            GROUP BY chaptersmaster.id, chaptersmaster.book, chaptersmaster.chapter
            ORDER BY chaptersmaster.id  -- Maintain Bible order
        `;

        // Fetch chapters for the current cycle
        db.all(allChaptersSql, [minReads], (err, chapters) => {
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

            // Render the progress view
            res.render('bible-progress', { chaptersByBook }, (err, html) => {
                if (err) {
                    return res.status(500).send('Error rendering progress');
                }
                res.send(html); // Return the HTML fragment for the modal
            });
        });
    });
});
app.get('/record', (req, res) => {
    if (!req.session.userId || !req.session.activeReaderId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const activeReaderId = req.session.activeReaderId;

    const chapterSql = `SELECT id, book, chapter FROM chaptersmaster ORDER BY id`;

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

        // Render the record page with active reader and chapters
        res.render('record', {
            userName: req.session.userName,
            activeReaderId, // Pass the activeReaderId directly from session
            chaptersByBook
        });
    });
});
app.post('/record', (req, res) => {
    if (!req.session.userId || !req.session.activeReaderId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const readerId = req.session.activeReaderId; // Use active reader ID from session
    const bookName = req.body.bookName;
    const startChapter = parseInt(req.body.startChapterId);
    const endChapter = parseInt(req.body.endChapterId);

    if (!bookName || !startChapter || !endChapter || startChapter > endChapter) {
        return res.status(400).send('Invalid chapter range or missing data.');
    }

    const chapters = Array.from({ length: endChapter - startChapter + 1 }, (_, i) => startChapter + i);
    recordChapters(userId, readerId, chapters, bookName, res, req, '/reader-profile');
});
// The function to generate a thank you message
async function generateThankYouMessage(readerName, pointsToAdd) {
    const prompt = `You will write as though you are Martin Luther the Reformer. You have a very high view of the Bible. You have a very low view of humanity. Write a two sentence thank-you message for a user named ${readerName} who has just reported chapters (which is a good thing) and earned ${pointsToAdd} points. Use sarcasm and be very pessimistic, though grateful that at least the user did something fruitful with their time. Keep the message short and do not include a formal closing or state your name. Make sure all your words fit within the time frame and religoius beliefs of early protestantism, salvation by grace alone through faith alone and in Christ alone, all to the glory of God alone.`;

    try {
        const response = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [{ role: "system", content: prompt }]
        });

        const message = response.choices[0].message.content;
        return message; // Return the message generated by ChatGPT
    } catch (error) {
        console.error('Error generating thank-you message:', error.message);
        return "Thank you for reporting chapters!"; // Fallback message
    }
}

app.post('/chatbot', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');  // Redirect to login if not logged in
    }

    // Check if there's an active reader selected
    const readerId = req.session.activeReaderId;
    const activeReaderName = req.session.activeReaderName;
    
    if (!readerId) {
        return res.redirect('/select-reader');  // Redirect to reader selection if no active reader
    }

    // Initialize conversations object if not present
    if (!req.session.conversations) {
        req.session.conversations = {};
    }

    const initialPrompt = `You are a helpful assistant that creates quizzes for the user, consisting of 5 multiple-choice Bible-based questions. Ask only one question at a time, wait for the user's response before asking the next question, and provide hints or Bible references if the user struggles. Track the user's score, and if they answer at least 4 questions correctly, call the addPoints function to reward them 5 points. Gradually increase the difficulty of quizzes as the user progresses. The active reader name is ${activeReaderName} with id ${readerId}.`;
    // console.log('the initial prompt:', initialPrompt)
    // Ensure system message is always present in the conversation
    if (!req.session.conversations[readerId]) {
        console.log(`Initializing conversation for reader ${readerId}`);
        req.session.conversations[readerId] = [
            { role: "system", content: initialPrompt }
        ];  // Initialize conversation for this reader
    } else {
        // Check if the exact system message already exists in the conversation
        const systemMessageExists = req.session.conversations[readerId].some(
            message => message.role === "system" && message.content.includes("You are a helpful assistant that creates quizzes")
        );
        if (!systemMessageExists) {
            console.log(`Adding system message to existing conversation for reader ${readerId}`);
            req.session.conversations[readerId].unshift({ role: "system", content: initialPrompt });
        }
    }
    const conversationPre = req.session.conversations[readerId];
    // console.log('Current conversation:', conversationPre);
    // Add the user's message to the conversation for the active reader
    req.session.conversations[readerId].push({ role: "user", content: req.body.message });

    const conversation = req.session.conversations[readerId];

    // console.log('Current conversation:', conversation);  // Log the conversation for debugging

    const tools = [
        {
            type: "function",
            function: {
                name: "addPoints",
                description: "Adds points to a reader",
                parameters: {
                    type: "object",
                    properties: {
                        readerId: { type: "number", description: "The ID of the reader" },
                        pointsToAdd: { type: "number", description: "Points to add" },
                    },
                    required: ["readerId", "pointsToAdd"]
                }
            }
        }
    ];
    // console.log(conversation);
    try {
        // Send message to OpenAI API with conversation history
        const response = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: conversation,  // Include conversation history
            tools: tools
        });

        const toolCall = response.choices[0].message.tool_calls?.[0];

        if (toolCall) {
            const { name, arguments: functionArgs } = toolCall.function;
            const parsedArgs = JSON.parse(functionArgs);

            if (name === "addPoints") {
                const { pointsToAdd } = parsedArgs;
                addPoints(readerId, pointsToAdd);  // Call your addPoints function
                const assistantMessage = `Added ${pointsToAdd} points to reader ${readerId}`;
                
                // Add assistant's response to the conversation history
                req.session.conversations[readerId].push({ role: "assistant", content: assistantMessage });
                res.send(assistantMessage);
            }
        } else {
            const assistantResponse = response.choices[0].message.content;

            // Add assistant's response to the conversation history
            req.session.conversations[readerId].push({ role: "assistant", content: assistantResponse });
            res.send(assistantResponse);
        }

    } catch (error) {
        console.error("Error with OpenAI chatbot:", error.message);
        res.status(500).send("Error interacting with chatbot.");
    }
});
app.post('/clear-conversation', (req, res) => {
    const readerId = req.session.activeReaderId;

    if (!readerId) {
        return res.status(400).send("No active reader selected.");
    }

    if (req.session.conversations && req.session.conversations[readerId]) {
        req.session.conversations[readerId] = [];  // Clear the conversation history for the active reader
        console.log(`Conversation cleared for reader ${readerId}.`);
        return res.send("Conversation history cleared for testing.");
    } else {
        return res.status(400).send("No conversation to clear for this reader.");
    }
});





// Update the recordChapters function to use OpenAI API
async function recordChapters(userId, readerId, chapters, bookName, res, req, redirectRoute, callback) {
    const insertChapterSql = `INSERT INTO user_chapters (user_id, reader_id, chapter_id) VALUES (?, ?, ?)`;
    const stmt = db.prepare(insertChapterSql);
    let totalPointsToAdd = 0;
    let pendingOperations = chapters.length;
    let hasErrorOccurred = false;

    // Fetch the reader's name for the thank-you message
    const readerNameSql = `SELECT reader_name FROM readers WHERE id = ?`;
    let readerName = "Reader"; // Default name if not found

    db.get(readerNameSql, [readerId], (err, row) => {
        if (!err && row) {
            readerName = row.reader_name; // Update with actual reader's name
        }
    });

    chapters.forEach(chapterId => {
        db.get(`SELECT id FROM chaptersmaster WHERE book = ? AND chapter = ?`, [bookName, chapterId], (err, row) => {
            if (err) {
                console.error(`Error finding chapter ${chapterId}:`, err.message);
                hasErrorOccurred = true;
            } else if (row) {
                checkForCompletion(readerId, row.id, (isCompletionChapter) => {
                    if (isCompletionChapter) {
                        totalPointsToAdd += 5; // 5 points for completion chapters
                    } else {
                        totalPointsToAdd += 1; // 1 point for regular chapters
                    }

                    stmt.run([userId, readerId, row.id], (err) => {
                        if (err) {
                            console.error(`Error inserting chapter ${chapterId}:`, err.message);
                            hasErrorOccurred = true;
                        }

                        pendingOperations--;

                        if (pendingOperations === 0) {
                            finalizeTransaction();
                        }
                    });
                });
            } else {
                console.error(`Chapter ${chapterId} not found.`);
                hasErrorOccurred = true;
                pendingOperations--;
                if (pendingOperations === 0) {
                    finalizeTransaction();
                }
            }
        });
    });

    async function finalizeTransaction() {
        stmt.finalize(async (err) => {
            if (err) {
                console.error('Error finalizing statement:', err.message);
                return res.status(500).send('Error recording chapters.');
            }

            if (hasErrorOccurred) {
                console.log('Some errors occurred during the process.');
                return res.status(500).send('Error occurred while recording some chapters.');
            }

            if (totalPointsToAdd > 0) {
                await addPoints(readerId, totalPointsToAdd);

                // Generate the thank-you message using ChatGPT
                const customMessage = await generateThankYouMessage(readerName, totalPointsToAdd);

                console.log(`${totalPointsToAdd} points added for readerId: ${readerId}`);
                // Flash the custom message
                req.flash('success', customMessage);
                res.redirect(redirectRoute);
            } else {
                res.redirect(redirectRoute);
            }

            // Call the callback if it exists and is a function
            if (typeof callback === 'function') {
                callback(null);
            }
        });
    }
}


function checkForCompletion(readerId, chapterId, callback) {
    const totalBibleChapters = 1189; // Total chapters in the Bible

    // Get the total number of times each chapter has been read by the reader
    const chapterReadsSql = `
        SELECT chapter_id, COUNT(chapter_id) AS times_read
        FROM user_chapters
        WHERE reader_id = ?
        GROUP BY chapter_id`;

    db.all(chapterReadsSql, [readerId], (err, rows) => {
        if (err) {
            console.error('Error retrieving chapter reads:', err.message);
            return callback(false);
        }

        let timesReadArray = new Array(totalBibleChapters).fill(0);

        // Populate the timesReadArray with the number of reads for each chapter
        rows.forEach(row => {
            timesReadArray[row.chapter_id - 1] = row.times_read;  // Subtract 1 because array index starts from 0
        });

        // Find the minimum number of times any chapter has been read
        const minReads = Math.min(...timesReadArray);

        // Check if this chapter is contributing to a new completion cycle
        callback(timesReadArray[chapterId - 1] === minReads);
    });
}

app.get('/record-by-book', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const activeReaderId = req.session.activeReaderId;
    const familySql = `SELECT family_id FROM users WHERE id = ?`;
    const readersSql = `SELECT readers.id, readers.reader_name 
                        FROM readers 
                        INNER JOIN family ON readers.family_id = family.id
                        WHERE family.id = ?`;
    
    // Fetch distinct books without sorting alphabetically, using the natural order in the database
    const booksSql = `SELECT DISTINCT book FROM chaptersmaster ORDER BY id`;

    // Get the user's family ID
    db.get(familySql, [userId], (err, familyRow) => {
        if (err || !familyRow) {
            console.error('Error retrieving family:', err.message);
            return res.status(500).send('Error retrieving family');
        }
        const familyId = familyRow.family_id;
        console.log('family id is: ',familyId)
        // Fetch all readers in the family
        db.all(readersSql, [familyId], (err, readers) => {
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
                res.render('record-by-book', { userName: req.session.userName, readers, books, activeReaderId });
            });
        });
    });
});
app.post('/record-by-book', (req, res) => {
    const userId = req.session.userId;
    const readerId = req.session.activeReaderId;
    let bookNames = req.body['bookName[]'];

    if (!Array.isArray(bookNames)) {
        bookNames = [bookNames];  // Convert single string to an array
    }

    if (!readerId || !bookNames || bookNames.length === 0) {
        return res.status(400).send('Missing required data.');
    }

    bookNames.forEach(bookName => {
        db.all(`SELECT chapter FROM chaptersmaster WHERE book = ?`, [bookName], (err, chapters) => {
            if (err || !chapters.length) {
                return res.status(500).send('Error retrieving chapters for the book.');
            }

            const chapterIds = chapters.map(chapter => chapter.chapter);
            recordChapters(userId, readerId, chapterIds, bookName, res, req, '/reader-profile');
        });
    });
});
// Route to fetch a chapter from the ESV API
app.get('/chapter/:book/:chapter', async (req, res) => {
    const book = req.params.book;
    const chapter = req.params.chapter;
    const chapterIdSql = `SELECT id FROM chaptersmaster WHERE book = ? AND chapter = ?`;

    try {
        // Fetch the chapter ID from the database
        const row = await new Promise((resolve, reject) => {
            db.get(chapterIdSql, [book, chapter], (err, row) => {
                if (err) {
                    return reject(err);
                }
                resolve(row);
            });
        });

        if (!row) {
            return res.status(404).send('Chapter not found');
        }
        
        const chapterId = row.id;  // Get the chapterId from the database

        // Make a request to the ESV API
        const esvResponse = await axios.get('https://api.esv.org/v3/passage/html/', {
            params: {
                q: `${book} ${chapter}`,  // e.g., 'John 1'
                'include-footnotes': false,
                'include-headings': true,
                'include-short-copyright': true
            },
            headers: {
                Authorization: `Token ${process.env.ESV_API_KEY}`
            }
        });

        // Extract the passage HTML
        const passageHTML = esvResponse.data.passages[0];

        // Render the HTML or pass it to the frontend
        res.render('chapter', { passageHTML, book, chapter, chapterId });

    } catch (error) {
        if (error.message === 'Chapter not found') {
            return res.status(404).send(error.message);
        }
        console.error('Error:', error.message);
        res.status(500).send('Error processing the request.');
    }
});

app.post('/mark-chapter-read', (req, res) => {
    const userId = req.session.userId;
    const readerId = req.session.activeReaderId;
    const bookName = req.body.bookName;
    const chapterNumber = parseInt(req.body.chapter); // Use chapter number, not chapterId

    if (!userId || !readerId || !bookName || !chapterNumber) {
        return res.status(400).send('Missing required data.');
    }

    // Fetch the correct chapterId from the database based on bookName and chapter number
    const chapterIdSql = `SELECT id FROM chaptersmaster WHERE book = ? AND chapter = ?`;

    db.get(chapterIdSql, [bookName, chapterNumber], (err, row) => {
        if (err) {
            console.error('Error retrieving chapter ID:', err.message);
            return res.status(500).send('Error retrieving chapter.');
        }
        if (!row) {
            return res.status(404).send('Chapter not found.');
        }

        const chapterId = row.id; // Correct chapterId fetched from the database

        // Now use the fetched chapterId in the recordChapters function
        recordChapters(userId, readerId, [chapterNumber], bookName, res, req, '/reader-profile', () => {
            console.log('Chapter marked as read and points updated.');
        });
    });
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
    const referralToken = generateReferralToken();

    if (!readerName || readerName.length > 20) {
        req.flash('error', 'Reader name cannot exceed 20 characters.');
        return res.redirect('/manage');
    }

    // Insert a new reader associated with the logged-in user's family
    const insertReaderSql = `INSERT INTO readers (family_id, reader_name, referral_token ) VALUES (?, ?, ?)`;
    const findNewReaderSql = `SELECT id FROM readers WHERE family_id = ? AND reader_name = ?`;
    db.run(insertReaderSql, [familyId, readerName, referralToken], function (err) {
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
            addPoints(readerId, 1);
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
    if (!req.session.userId) {
        return res.status(403).send('Access denied');
    }
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
    if (!req.session.userId) {
        return res.status(403).send('Access denied');
    }
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
          // Truncate email addresses to a max of 20 characters
          const maxEmailLength = 15;
          users = users.map(user => {
              return {
                  ...user,
                  truncatedEmail: user.email.length > maxEmailLength ? user.email.substring(0, maxEmailLength) + '...' : user.email
              };
          });
        res.render('admin', { users });
    });
    
});
app.get('/admin-levels', (req, res) => {
    if (!req.session.userId || req.session.role !== 'admin') {
        return res.status(403).send('Access denied');
    }
    db.all('SELECT * FROM levels', [], (err, levels) => {
        if (err) {
            console.error('Error retrieving levels:', err.message);
            return res.status(500).send('Error retrieving levels');
        }
        res.render('admin-levels', { levels });
    });
});
app.post('/admin/levels/update', (req, res) => {
    if (!req.session.userId || req.session.role !== 'admin') {
        return res.status(403).send('Access denied');
    }
    const { id, level_name, min_points, description } = req.body;
    const updateLevelSql = `UPDATE levels SET level_name = ?, min_points = ?, description = ? WHERE id = ?`;
    db.run(updateLevelSql, [level_name, min_points, description, id], function (err) {
        if (err) {
            console.error('Error updating level:', err.message);
            return res.status(500).send('Error updating level');
        }
        req.flash('success', `you updated the levels table!`);
        res.redirect('/admin-levels'); // Redirect back to the levels page after the update
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
// POST route to clear userpoints and userchapters
app.post('/admin/clear-tables', (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).send('Access denied');
    }

    // SQL commands to clear userpoints and userchapters tables
    const deleteUserPointsSql = `DELETE FROM userpoints`;
    const deleteUserChaptersSql = `DELETE FROM user_chapters`;
    const resetUserChaptersSeqSql = `DELETE FROM sqlite_sequence WHERE name='user_chapters'`;

    // First, clear the userpoints and userchapters tables
    db.run(deleteUserPointsSql, (err) => {
        if (err) {
            console.error('Error deleting userpoints:', err.message);
            return res.status(500).send('Error clearing userpoints table.');
        }
        console.log("cleared points");
        db.run(deleteUserChaptersSql, (err) => {
            if (err) {
                console.error('Error deleting userchapters:', err.message);
                return res.status(500).send('Error clearing userchapters table.');
            }
            db.run(resetUserChaptersSeqSql, (err) => {
                if (err) {
                    console.error('Error resetting userchapters sequence:', err.message);
                    return res.status(500).send('Error resetting userchapters sequence.');
                }

                // After clearing, insert a row into userpoints for each reader
                const getReadersSql = `SELECT id FROM readers`;  // Get all reader IDs
                db.all(getReadersSql, [], (err, readers) => {
                    if (err) {
                        console.error('Error retrieving readers:', err.message);
                        return res.status(500).send('Error retrieving readers.');
                    }

                    // Insert 1 point for each reader in the userpoints table
                    const insertPointsSql = `INSERT INTO userpoints (reader_id, user_points) VALUES (?, 1)`;
                    readers.forEach(reader => {
                        db.run(insertPointsSql, [reader.id], (err) => {
                            if (err) {
                                console.error(`Error inserting points for reader ${reader.id}:`, err.message);
                            } else {
                                console.log(`Inserted 1 point for reader ${reader.id}`);
                            }
                        });
                    });

                    // After all operations are successful, redirect back to the admin page
                    req.flash('success', 'User points and chapters cleared and reset successfully!');
                    res.redirect('/admin');
                });
            });
        });
    });
});


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
function addPoints(readerId, pointsToAdd, callback) {
    const checkSql = `SELECT user_points FROM userpoints WHERE reader_id = ?`;

    db.get(checkSql, [readerId], (err, row) => {
        if (err) {
            console.error("Error checking for existing points:", err.message);
            return callback(err); // Pass the error to the callback
        }

        if (row) {
            const newPoints = row.user_points + pointsToAdd;
            const updateSql = `UPDATE userpoints SET user_points = ? WHERE reader_id = ?`;

            db.run(updateSql, [newPoints, readerId], (err) => {
                if (err) {
                    console.error("Error updating points:", err.message);
                    return callback(err); // Pass the error to the callback
                }

                console.log(`Updated points for reader ${readerId}. New total: ${newPoints}`);
                updateReaderLevel(readerId, newPoints, callback); // Pass the callback to updateReaderLevel
            });
        } else {
            const insertSql = `INSERT INTO userpoints (reader_id, user_points) VALUES (?, ?)`;

            db.run(insertSql, [readerId, pointsToAdd], (err) => {
                if (err) {
                    console.error("Error inserting new points:", err.message);
                    return callback(err); // Pass the error to the callback
                }

                console.log(`Inserted ${pointsToAdd} points for reader ${readerId}.`);
                updateReaderLevel(readerId, pointsToAdd, callback); // Pass the callback to updateReaderLevel
            });
        }
    });
}

function updateReaderLevel(readerId, totalPoints, callback) {
    const levelSql = `SELECT id, level_name FROM levels WHERE min_points <= ? ORDER BY min_points DESC LIMIT 1`;

    db.get(levelSql, [totalPoints], (err, level) => {
        if (err) {
            console.error('Error fetching level:', err.message);
            if (typeof callback === 'function') {
                return callback(err);
            }
        }

        else if (level) {
            const updateLevelSql = `UPDATE readers SET current_level_id = ? WHERE id = ?`;

            db.run(updateLevelSql, [level.id, readerId], (err) => {
                if (err) {
                    console.error('Error updating reader level:', err.message);
                    if (typeof callback === 'function') {
                        return callback(err);
                    }
                }

                console.log(`Updated reader ${readerId} to level: ${level.level_name}`);
                if (typeof callback === 'function') {
                    callback(null);
                }
            });
        } else {
            if (typeof callback === 'function') {
                callback(null);
            }
        }
    });
}

function generateReferralToken() {
    return crypto.randomBytes(16).toString('hex'); // Creates a unique token
}
app.get('/leaderboard', (req, res) => {
    // Query to get the top 10 readers by points and their level ID
    const leaderboardSql = `
        SELECT readers.reader_name, SUM(userpoints.user_points) as total_points, readers.current_level_id
        FROM userpoints
        JOIN readers ON userpoints.reader_id = readers.id
        GROUP BY readers.reader_name, readers.current_level_id
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

const PORT = 80;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
