/* ////////////
Setup imports
//////////////*/
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
import { addReadingPlan } from './utils.js';
sqlite3.verbose();
const SQLiteStore = connectSqlite3(session);
dotenv.config();
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const app = express();
import { fileURLToPath } from 'url';
import { dirname } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

//app.* stuff
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(expressLayouts);
app.set('layout', 'layout');
app.use(session({
    store: new SQLiteStore({ db: '../sessions.sqlite' }),
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
app.use((req, res, next) => {
    res.locals.successMessage = req.flash('success');
    res.locals.errorMessage = req.flash('error');
    next();
});
function isAdmin(req, res, next) {
    if (req.session.role !== 'admin') {
        return res.redirect('/');
    }
    next();
}
let db = new sqlite3.Database('../mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the SQLite database.');
});
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

    // First, get the family_id for the logged-in user
    const userSql = `SELECT family_id FROM users WHERE id = ?`;

    db.get(userSql, [req.session.userId], (err, user) => {
        if (err) {
            console.error('Error retrieving user family ID:', err.message);
            return res.status(500).send('Error retrieving user family ID.');
        }

        if (!user || !user.family_id) {
            console.error('No family ID found for user.');
            return res.redirect('/manage');
        }

        // Fetch the readers for the user's family_id
        const familySql = `SELECT id, reader_name FROM readers WHERE family_id = ?`;

        db.all(familySql, [user.family_id], (err, readers) => {
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
    const activeReaderId = req.session.activeReaderId; // Active reader ID from session
    const totalBibleChapters = 1189; // Total chapters in the Bible

    // SQL query to get the selected reading plan for the active reader
    const readingPlanSql = `
        SELECT rp.chapter_ids
        FROM reading_plans rp
        JOIN reader_plans rpl ON rp.id = rpl.plan_id
        WHERE rpl.reader_id = ?
    `;

    db.get(readingPlanSql, [activeReaderId], (err, plan) => {
        if (err) {
            console.error('Error fetching the reading plan:', err.message);
            return res.status(500).send('Error retrieving reading plan');
        }

        // If a plan exists, parse the chapter IDs from JSON; otherwise, use the full Bible
        let chapterFilter = null;
        if (plan && plan.chapter_ids) {
            chapterFilter = JSON.parse(plan.chapter_ids); // Parse the JSON array of chapter IDs
        }

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

            // Fetch chapters for the current cycle, filtering by active reader and taking into account minReads
            let allChaptersSql = `
                SELECT chaptersmaster.id, chaptersmaster.book, chaptersmaster.chapter,
                       CASE WHEN COUNT(user_chapters.chapter_id) > ? THEN 1 ELSE 0 END as is_read
                FROM chaptersmaster
                LEFT JOIN user_chapters ON chaptersmaster.id = user_chapters.chapter_id
                                       AND user_chapters.reader_id = ?  -- Filter by the active reader
            `;

            // If a reading plan exists, only fetch chapters within the reading plan's chapter IDs
            if (chapterFilter) {
                const chapterIdList = chapterFilter.join(",");  // Convert array of chapter IDs to a comma-separated string
                allChaptersSql += ` WHERE chaptersmaster.id IN (${chapterIdList}) `;
            }

            allChaptersSql += `
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
});
app.get('/select-reading-plan', (req, res) => {
    const activeReaderId = req.session.activeReaderId; // Assuming active reader ID is in the session

    // SQL query to fetch all available reading plans
    const availablePlansSql = `SELECT id, name FROM reading_plans`;

    db.all(availablePlansSql, [], (err, plans) => {
        if (err) {
            console.error('Error fetching reading plans:', err.message);
            return res.status(500).send('Error retrieving reading plans.');
        }

        // Fetch the current plan for the reader
        const currentPlanSql = `SELECT plan_id FROM reader_plans WHERE reader_id = ?`;
        db.get(currentPlanSql, [activeReaderId], (err, currentPlan) => {
            if (err) {
                console.error('Error fetching current reading plan:', err.message);
                return res.status(500).send('Error retrieving current plan.');
            }

            // Render the selection page
            res.render('select-reading-plan', {
                plans,
                currentPlanId: currentPlan ? currentPlan.plan_id : null
            });
        });
    });
});
app.post('/update-reading-plan', (req, res) => {
    const activeReaderId = req.session.activeReaderId;
    const { planId } = req.body;

    if (!activeReaderId) {
        return res.status(400).send('Invalid request. Missing reader information.');
    }

    if (!planId) {
        // If no plan is selected (revert to whole Bible), delete the current plan
        const deletePlanSql = `DELETE FROM reader_plans WHERE reader_id = ?`;
        db.run(deletePlanSql, [activeReaderId], (err) => {
            if (err) {
                console.error('Error deleting reading plan:', err.message);
                return res.status(500).send('Error resetting reading plan.');
            }
            req.flash('success', 'Reading plan reset to whole Bible!');
            return res.redirect('/reader-progress');
        });
    } else {
        // If a plan is selected, update or insert it
        const checkPlanSql = `SELECT * FROM reader_plans WHERE reader_id = ?`;

        db.get(checkPlanSql, [activeReaderId], (err, row) => {
            if (err) {
                console.error('Error checking existing plan:', err.message);
                return res.status(500).send('Error updating reading plan.');
            }

            if (row) {
                // Update the existing plan
                const updatePlanSql = `UPDATE reader_plans SET plan_id = ? WHERE reader_id = ?`;
                db.run(updatePlanSql, [planId, activeReaderId], (err) => {
                    if (err) {
                        console.error('Error updating plan:', err.message);
                        return res.status(500).send('Error updating reading plan.');
                    }
                    req.flash('success', 'Reading plan updated successfully!');
                    return res.redirect('/reader-progress');
                });
            } else {
                // Insert a new plan if no plan exists
                const insertPlanSql = `INSERT INTO reader_plans (reader_id, plan_id) VALUES (?, ?)`;
                db.run(insertPlanSql, [activeReaderId, planId], (err) => {
                    if (err) {
                        console.error('Error inserting new plan:', err.message);
                        return res.status(500).send('Error updating reading plan.');
                    }
                    req.flash('success', 'Reading plan set successfully!');
                    return res.redirect('/reader-progress');
                });
            }
        });
    }
});
app.get('/create-custom-plan', (req, res) => {
    const activeReaderId = req.session.activeReaderId;

    // Fetch all chapters to display for selection
    const fetchChaptersSql = `SELECT id, book, chapter FROM chaptersmaster ORDER BY id`;

    db.all(fetchChaptersSql, [], (err, chapters) => {
        if (err) {
            console.error('Error fetching chapters:', err.message);
            return res.status(500).send('Error fetching chapters.');
        }

        // Render the chapter selection form
        res.render('create-custom-plan', { chapters });
    });
});
app.post('/create-custom-plan', (req, res) => {
    const { planName, chapters } = req.body;
    const activeReaderId = req.session.activeReaderId;

    if (!planName || !chapters) {
        return res.status(400).send('Plan name and chapters are required.');
    }

    // Convert chapters to integers and ensure it's an array
    const selectedChapters = Array.isArray(chapters) ? chapters.map(Number) : [parseInt(chapters)];

    // Insert the new custom plan
    addReadingPlan(planName, selectedChapters, (err, planId) => {
        if (err) {
            console.error('Error creating custom plan:', err.message);
            return res.status(500).send('Error creating custom plan.');
        }

        // Assign the new plan to the user
        const insertReaderPlanSql = `INSERT INTO reader_plans (reader_id, plan_id) VALUES (?, ?)`;
        db.run(insertReaderPlanSql, [activeReaderId, planId], (err) => {
            if (err) {
                console.error('Error assigning plan to reader:', err.message);
                return res.status(500).send('Error assigning plan.');
            }
            req.flash('success', 'Custom reading plan created successfully!');
            res.redirect('/reader-progress');
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
                    // First, check if the reader already has points in the userpoints table
                    const checkPointsSql = `SELECT user_points FROM userpoints WHERE reader_id = ?`;
                
                    db.get(checkPointsSql, [referringReaderId], (err, row) => {
                        if (err) {
                            console.error('Error checking for existing points:', err.message);
                        } else if (row) {
                            // If the reader already has points, update the existing row
                            const updatePointsSql = `UPDATE userpoints SET user_points = user_points + ? WHERE reader_id = ?`;
                            db.run(updatePointsSql, [25, referringReaderId], (err) => {
                                if (err) {
                                    console.error('Error updating referral points:', err.message);
                                } else {
                                    // Add flash message for the referring reader
                                    req.session.flashMessage = 'You have earned 25 points from a referral!';
                                }
                            });
                        } else {
                            // If the reader does not have points, insert a new row
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
app.get('/todays-reading', (req, res) => {
    const readerId = req.session.activeReaderId;

    // Start and end of the reading challenge
    const challengeStartDate = new Date('2024-09-29');
    const challengeEndDate = new Date('2024-10-27');
    const today = new Date();
    let statusMessage = '';

    // Check if today is before the challenge start date
    if (today < challengeStartDate) {
        const readStarts = Math.ceil((challengeStartDate - today) / (1000 * 60 * 60 * 24));
        statusMessage = `The reading challenge starts in ${readStarts} days.`;
    } else if (today > challengeEndDate) {
        statusMessage = 'The reading challenge is over.';
    }

    // Calculate the number of days remaining in the challenge
    const daysRemaining = Math.ceil((challengeEndDate - today) / (1000 * 60 * 60 * 24));

    console.log(`Days remaining in the challenge: ${daysRemaining}`);

    if (daysRemaining <= 0) {
        return res.status(400).send('The reading challenge period is over.');
    }

    // Fetch reader's plan
    const planSql = `
        SELECT rp.chapter_ids
        FROM reading_plans rp
        JOIN reader_plans rpl ON rp.id = rpl.plan_id
        WHERE rpl.reader_id = ?
    `;

    console.log(`Fetching plan for readerId: ${readerId}`);

    db.get(planSql, [readerId], (err, plan) => {
        if (err) {
            console.error('Error fetching reading plan:', err.message);
            return res.status(500).send('Error fetching reading plan.');
        }

        if (!plan) {
            console.log('No reading plan found for this reader.');
            statusMessage = 'You have not selected a reading plan.';
            const chapters = '';
            return res.render('todays-reading', { chapters, readerName: req.session.activeReaderName, statusMessage });

        }

        console.log(`Reading plan found: ${JSON.stringify(plan)}`);

        const chapterIds = JSON.parse(plan.chapter_ids);
        const totalChapters = chapterIds.length;
        const challengeDays = Math.ceil((challengeEndDate - challengeStartDate) / (1000 * 60 * 60 * 24));
        const chaptersPerDay = Math.ceil(totalChapters / challengeDays);

        // Calculate today's chapters
        const todayIndex = Math.max(0, totalChapters - (daysRemaining * chaptersPerDay));
        console.log(`TodayIndex: ${todayIndex}, Chapters per day: ${chaptersPerDay}`);

        const todaysChapters = chapterIds.slice(todayIndex, todayIndex + chaptersPerDay);
        console.log(`Today's chapters: ${JSON.stringify(todaysChapters)}`);

        // Fetch chapter info for today's chapters
        const chaptersSql = `SELECT book, chapter FROM chaptersmaster WHERE id IN (${todaysChapters.join(',')})`;

        console.log(`Executing SQL: ${chaptersSql}`);

        db.all(chaptersSql, [], (err, chapters) => {
            if (err) {
                console.error('Error fetching today\'s chapters:', err.message);
                return res.status(500).send('Error fetching today\'s chapters.');
            }

            console.log(`Fetched chapters: ${JSON.stringify(chapters)}`);

            res.render('todays-reading', { chapters, readerName: req.session.activeReaderName, statusMessage });
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

        // SQL query to get the number of unique readers who have at least one chapter reported
    const uniqueReadersSql = `
        SELECT COUNT(DISTINCT reader_id) AS uniqueReaders
        FROM user_chapters
    `;
    // Fetch total chapters read across all users
    db.get(totalChaptersSql, (err, totalRow) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Error retrieving total chapters');
        }

        const totalChaptersRead = totalRow.total; // Total chapters read across all users

        db.get(uniqueReadersSql, (err, readerRow) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send('Error retrieving unique readers');
            }

            const uniqueReadersCount = readerRow.uniqueReaders;

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
                            uniqueReadersCount,
                            isLoggedIn: true
                        });
                        });       
                    });
                });
            });
        });
    });
});
app.get('/book-progress', (req, res) => {
    // SQL to get the read counts for each chapter, preserving the order of books as in chaptersmaster
    const chapterReadCountsSql = `
        SELECT chaptersmaster.book, chaptersmaster.chapter, COUNT(user_chapters.chapter_id) AS read_count
        FROM chaptersmaster
        LEFT JOIN user_chapters ON chaptersmaster.id = user_chapters.chapter_id
        GROUP BY chaptersmaster.book, chaptersmaster.chapter
        ORDER BY MIN(chaptersmaster.id)
    `;

    db.all(chapterReadCountsSql, (err, chapterReadCounts) => {
        if (err) {
            console.error('Error retrieving chapter read counts:', err.message);
            return res.status(500).send('Error retrieving chapter read counts');
        }

        // Create a map to track the lowest read count for each book
        let bookCompletionCounts = {};

        // Iterate over each chapter's read count and determine the minimum read count for each book
        chapterReadCounts.forEach(row => {
            const { book, read_count } = row;

            // Initialize the book in the map if it doesn't exist yet
            if (!bookCompletionCounts[book]) {
                bookCompletionCounts[book] = read_count || 0;
            }

            // Update the book's completion count with the minimum read count
            bookCompletionCounts[book] = Math.min(bookCompletionCounts[book], read_count || 0);
        });

        // Prepare data for rendering in the order of appearance in chaptersmaster
        const bookProgress = Object.keys(bookCompletionCounts).map(book => ({
            book,
            completions: Math.min(bookCompletionCounts[book], 20) // Cap the completion count at 20
        }));

        // Render the progress view
        res.render('book-progress', { bookProgress });
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

    // Use recordChapters and handle the response after completion
    recordChapters(userId, readerId, chapters, bookName, res, req, '/reader-profile', (err) => {
        if (err) {
            console.error('Error recording chapters:', err);
            return res.status(500).send('Error recording chapters.');
        }

        // Once the chapters have been recorded, redirect to the reader profile
        
    });
});

// The function to generate a thank you message
async function generateThankYouMessage(readerName, pointsToAdd) {
    const assistantId = "asst_KuigPHVlLvD7qsOwcwRXUuXp"; // Replace with the actual assistant ID from your OpenAI Assistant

    try {
        // Create a thread for the conversation
        const thread = await openai.beta.threads.create();

        // Add the user's message (you can add system context too, but your assistant will handle that)
        await openai.beta.threads.messages.create(thread.id, {
            role: 'user',
            content: `Reader ${readerName} has earned ${pointsToAdd} points. Generate a thank you message.`
        });

        // Create a run with the assistant
        let run = await openai.beta.threads.runs.createAndPoll(thread.id, {
            assistant_id: assistantId
        });
        console.log(run); // Log the entire response object for debugging

        if (run.status === 'completed') {
            const messages = await openai.beta.threads.messages.list(run.thread_id);
            
            // Find the first message from the assistant and return it
            for (const message of messages.data.reverse()) {
                if (message.role === 'assistant') {
                    return message.content[0].text.value;  // Return only the assistant's message
                }
            }
        } else {
            console.log(run.status);
        }
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

    const initialPrompt = `You are a Bible Quiz generator. You will be given a user name and a request for a quiz. The quiz will be 5 multiple choice questions about the protestant Bible. Ask the questions one at a time. If the user gets at least 4 correct, award 5 points. If the user asks for a harder quiz, you may make a judgement of how many points to award in the range of 5 to 15 points.  You will speak as though you are Martin Luther, the 16th century german reformer. He is not exactly excited to be providing this quiz. But he does at least consider it to be far greater than whatever other worldly folly the reader might have otherwise been doing. While he interacts with the reader, and offers congratulations on success, he will always remind the reader that it is only faith in the finished work of Christ that merits salvation and not to put too much stock in earning points, admitting only that the effort may slightly contribute to growth in maturity.  The active reader name is ${activeReaderName} with id ${readerId}.`;
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
app.get('/claim-points', (req, res) => {
    const readerId = req.session.activeReaderId;

    if (!readerId) {
        return res.redirect('/login');
    }

    // Run the script to process new completions before loading the points page
    processNewCompletions();

    // Query to get the reader's entries in chapters_completion
    const getChaptersSql = `
        SELECT chapter_id, COALESCE(completion_order, 0) * 2 AS points, completion_cycle, points_claimed 
        FROM chapters_completion 
        WHERE reader_id = ? 
        ORDER BY points_claimed ASC, completion_cycle DESC, completion_order DESC
    `;

    db.all(getChaptersSql, [readerId], (err, rows) => {
        if (err) {
            console.error('Error retrieving completion chapters:', err.message);
            return res.status(500).send('Error retrieving completion chapters');
        }
        console.log('Chapters:', rows);
        // Render the page and pass the chapters list
        res.render('claim-points', { chapters: rows });
    });
});
app.post('/claim-points', (req, res) => {
    const readerId = req.session.activeReaderId;

    if (!readerId) {
        console.log("No active reader ID in session.");
        return res.redirect('/login');
    }

    // Convert the chapters to an array, even if only one chapter is selected
    let chaptersToClaim = req.body.chapters;
    if (!chaptersToClaim) {
        req.flash('error', 'No chapters selected.');
        return res.redirect('/claim-points');
    }

    if (!Array.isArray(chaptersToClaim)) {
        chaptersToClaim = [chaptersToClaim]; // Convert single value to array
    }

    // Step 1: Fetch the details of the chapters to claim from the database
    const getChapterDetailsSql = `
        SELECT chapter_id, completion_order 
        FROM chapters_completion 
        WHERE reader_id = ? AND chapter_id IN (${chaptersToClaim.map(() => '?').join(',')})
    `;

    db.all(getChapterDetailsSql, [readerId, ...chaptersToClaim], (err, rows) => {
        if (err) {
            console.error('Error retrieving chapter details:', err.message);
            return res.status(500).send('Error retrieving chapter details');
        }

        // Step 2: Calculate the total points based on the completion_order (doubled)
        let totalPoints = 0;
        rows.forEach(row => {
            totalPoints += row.completion_order * 2;
        });

        console.log(`Adding ${totalPoints} points to reader ${readerId}. Chapters to claim:`, chaptersToClaim);

        // Step 3: Add the calculated points to the reader
        addPoints(readerId, totalPoints, (err) => {
            if (err) {
                console.error('Error adding points:', err.message);
                return res.status(500).send('Error adding points');
            }

            // Step 4: Update the chapters_completion table to mark these chapters as claimed
            const updateChaptersSql = `
                UPDATE chapters_completion 
                SET points_claimed = 1 
                WHERE reader_id = ? AND chapter_id IN (${chaptersToClaim.map(() => '?').join(',')})
            `;

            db.run(updateChaptersSql, [readerId, ...chaptersToClaim], (err) => {
                if (err) {
                    console.error('Error updating chapters as claimed:', err.message);
                    return res.status(500).send('Error updating chapters as claimed');
                }

                console.log(`${totalPoints} points successfully claimed for reader ${readerId}.`);
                req.flash('success', `${totalPoints} points claimed!`);
                res.redirect('/claim-points');
            });
        });
    });
});
function processNewCompletions(callback) {
    // Step 1: Check the last processed completion cycle
    const getLastProcessedCycleSql = `
        SELECT MAX(completion_cycle) AS last_cycle 
        FROM chapters_completion
    `;

    db.get(getLastProcessedCycleSql, [], (err, row) => {
        if (err) {
            console.error('Error retrieving last processed cycle:', err.message);
            if (callback) callback(err);
            return;
        }

        const lastProcessedCycle = row.last_cycle || 0;  // Default to 0 if no cycle has been processed

        // Step 2: Process new completion cycles starting from lastProcessedCycle + 1
        getLoopCount((loopCount) => {
            if (loopCount <= lastProcessedCycle) {
                console.log('No new completion cycles to process.');
                if (callback) callback(null); // No new cycles, callback as success
                return;
            }

            console.log(`Processing new completions from cycle ${lastProcessedCycle + 1} to ${loopCount}`);
            let cyclesProcessed = 0;

            // Process new cycles in sequence
            for (let i = lastProcessedCycle + 1; i <= loopCount; i++) {
                processCompletionCycle(i, (err) => {
                    if (err) {
                        console.error(`Error processing cycle ${i}:`, err);
                    } else {
                        console.log(`Successfully processed cycle ${i}`);
                    }

                    // Once all cycles have been processed, trigger the callback
                    cyclesProcessed++;
                    if (cyclesProcessed === loopCount - lastProcessedCycle) {
                        if (callback) callback(null);
                    }
                });
            }
        });
    });
}
function processCompletionCycle(completionCycle, callback) {
    console.log(`Processing completion cycle: ${completionCycle}`);

    // SQL query to get the nth occurrence of each chapter (based on completionCycle)
    const sqlQuery = `
        WITH RankedChapters AS (
            SELECT chapter_id, reader_id, timestamp, 
            ROW_NUMBER() OVER (PARTITION BY chapter_id ORDER BY timestamp ASC) AS rank 
            FROM user_chapters
        )
        SELECT chapter_id, reader_id, timestamp 
        FROM RankedChapters 
        WHERE rank = ? 
        ORDER BY timestamp DESC 
        LIMIT 25;
    `;

    db.all(sqlQuery, [completionCycle], (err, rows) => {
        if (err) {
            console.error(`Error fetching data for cycle ${completionCycle}:`, err.message);
            return callback(err);
        }

        if (rows.length === 0) {
            console.log(`No data found for completion cycle: ${completionCycle}`);
            return callback(null);
        }

        let completedCount = 0;

        // Insert the rows into the chapters_completion table only if they don't exist
        rows.forEach((row, index) => {
            const checkIfExistsSql = `
                SELECT 1 FROM chapters_completion
                WHERE reader_id = ? AND chapter_id = ? AND completion_cycle = ?
            `;

            db.get(checkIfExistsSql, [row.reader_id, row.chapter_id, completionCycle], (err, result) => {
                if (err) {
                    console.error(`Error checking if completion chapter exists for cycle ${completionCycle}:`, err.message);
                    return;
                }

                // If it doesn't exist, insert the new entry
                if (!result) {
                    const insertSql = `
                        INSERT INTO chapters_completion (reader_id, chapter_id, timestamp, completion_cycle, completion_order)
                        VALUES (?, ?, ?, ?, ?);
                    `;
                    db.run(insertSql, [row.reader_id, row.chapter_id, row.timestamp, completionCycle, 25 - index], (err) => {
                        if (err) {
                            console.error(`Error inserting completion data for cycle ${completionCycle}:`, err.message);
                        } else {
                            completedCount++;
                            if (completedCount === rows.length) {
                                callback(null);
                            }
                        }
                    });
                } else {
                    console.log(`Chapter already exists for cycle ${completionCycle}, skipping...`);
                    completedCount++;
                    if (completedCount === rows.length) {
                        callback(null);
                    }
                }
            });
        });
    });
}

// Helper function to get the loop count (number of total completion cycles)
function getLoopCount(callback) {
    const getMinOccurrencesSql = `
        SELECT MIN(chapter_count) AS lowest_occurrences 
        FROM (SELECT chapter_id, COUNT(*) AS chapter_count 
              FROM user_chapters GROUP BY chapter_id) AS chapter_counts
    `;

    db.get(getMinOccurrencesSql, [], (err, row) => {
        if (err) {
            console.error('Error retrieving the minimum occurrences:', err.message);
            return;
        }

        const loopCount = row.lowest_occurrences || 0;  // Set the loopCount based on the minimum occurrences
        console.log(`Loop count set to: ${loopCount}`);
        callback(loopCount);
    });
}
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
                if (!hasErrorOccurred) {
                    hasErrorOccurred = true;
                    return callback(err);
                }
            }

            if (hasErrorOccurred) {
                return; // Make sure no further operations run if there's an error
            }

            if (totalPointsToAdd > 0) {
                await addPoints(readerId, totalPointsToAdd);

                // Generate the thank-you message using ChatGPT
                const customMessage = await generateThankYouMessage(readerName, totalPointsToAdd);

                console.log(`${totalPointsToAdd} points added for readerId: ${readerId}`);
                // Flash the custom message
                req.flash('success', customMessage);
                if (!hasErrorOccurred) {
                    res.redirect(redirectRoute);
                }
            } else if (!hasErrorOccurred) {
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

    // Process each book and let recordChapters handle the redirect for each one
    bookNames.forEach(bookName => {
        db.all(`SELECT chapter FROM chaptersmaster WHERE book = ?`, [bookName], (err, chapters) => {
            if (err || !chapters.length) {
                console.error('Error retrieving chapters for the book:', err);
                return res.status(500).send('Error retrieving chapters for the book.');
            }

            const chapterIds = chapters.map(chapter => chapter.chapter);

            // Let recordChapters handle the redirect
            recordChapters(userId, readerId, chapterIds, bookName, res, req, '/reader-profile', (err) => {
                if (err) {
                    console.error('Error recording chapters:', err);
                    return res.status(500).send('Error recording chapters.');
                }

                console.log(`Chapters from ${bookName} recorded.`);
            });
        });
    });
});

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

        // Make a request to the ESV API for the passage HTML
        const esvResponse = await axios.get('https://api.esv.org/v3/passage/html/', {
            params: {
                q: `${book} ${chapter}`,  // e.g., 'John 1'
                'include-footnotes': false,
                'include-headings': true,
                'include-short-copyright': true,
                'include-audio-link': false
            },
            headers: {
                Authorization: `Token ${process.env.ESV_API_KEY}`
            }
        });

        // Make a request to the ESV API for the audio passage
        const audioResponse = await axios.get('https://api.esv.org/v3/passage/audio/', {
            params: {
                q: `${book} ${chapter}`
            },
            headers: {
                Authorization: `Token ${process.env.ESV_API_KEY}`
            }
        });

        // Extract the passage HTML and audio URL
        const passageHTML = esvResponse.data.passages[0];
        const audioUrl = audioResponse.request.res.responseUrl;  // Get the final redirect URL

        // Render the HTML or pass it to the frontend
        res.render('chapter', { passageHTML, book, chapter, chapterId, audioUrl });

    } catch (error) {
        if (error.message === 'Chapter not found') {
            return res.status(404).send(error.message);
        }
        console.error('Error:', error.message);
        res.status(500).send('Error processing the request.');
    }
});
app.get('/group/chapter/:book/:chapter', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const book = req.params.book;
    const chapter = req.params.chapter;

    const chapterIdSql = `SELECT id FROM chaptersmaster WHERE book = ? AND chapter = ?`;
    const familySql = `SELECT readers.id, readers.reader_name FROM readers WHERE family_id = (SELECT family_id FROM users WHERE id = ?)`;

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

        // Fetch the readers from the logged-in user's family
        const readers = await new Promise((resolve, reject) => {
            db.all(familySql, [userId], (err, rows) => {
                if (err) {
                    return reject(err);
                }
                resolve(rows);
            });
        });

        if (readers.length === 0) {
            return res.status(404).send('No readers found for the user’s family.');
        }

        // Make a request to the ESV API for the passage HTML
        const esvResponse = await axios.get('https://api.esv.org/v3/passage/html/', {
            params: {
                q: `${book} ${chapter}`,  // e.g., 'John 1'
                'include-footnotes': false,
                'include-headings': true,
                'include-short-copyright': true,
                'include-audio-link': false
            },
            headers: {
                Authorization: `Token ${process.env.ESV_API_KEY}`
            }
        });

        // Make a request to the ESV API for the audio passage
        const audioResponse = await axios.get('https://api.esv.org/v3/passage/audio/', {
            params: {
                q: `${book} ${chapter}`
            },
            headers: {
                Authorization: `Token ${process.env.ESV_API_KEY}`
            }
        });

        // Extract the passage HTML and audio URL
        const passageHTML = esvResponse.data.passages[0];
        const audioUrl = audioResponse.request.res.responseUrl;  // Get the final redirect URL

        // Render the HTML or pass it to the frontend with readers data
        res.render('group-chapters', { passageHTML, book, chapter, chapterId, audioUrl, readers });

    } catch (error) {
        if (error.message === 'Chapter not found') {
            return res.status(404).send(error.message);
        }
        console.error('Error:', error.message);
        res.status(500).send('Error processing the request.');
    }
});

async function recordGroupRead(userId, readerIds, chapters, bookName, res, req, redirectRoute, callback) {
    const insertChapterSql = `INSERT INTO user_chapters (user_id, reader_id, chapter_id) VALUES (?, ?, ?)`;
    const stmt = db.prepare(insertChapterSql);
    let totalPointsForReaders = {};  // Object to accumulate points for each reader
    let pendingOperations = readerIds.length * chapters.length; // Total operations (readers * chapters)
    let hasErrorOccurred = false;

    // Fetch the chapter IDs from the chaptersmaster table
    chapters.forEach(chapterId => {
        db.get(`SELECT id FROM chaptersmaster WHERE book = ? AND chapter = ?`, [bookName, chapterId], (err, row) => {
            if (err || !row) {
                console.error(`Error finding chapter ${chapterId}:`, err ? err.message : 'Chapter not found');
                hasErrorOccurred = true;
                pendingOperations -= readerIds.length; // Reduce pending operations for each reader
                if (pendingOperations === 0) finalizeTransaction();
            } else {
                const chapterMasterId = row.id;

                // For each reader, mark the chapter as read and calculate points
                readerIds.forEach(readerId => {
                    db.get(`SELECT COUNT(*) AS times_read FROM user_chapters WHERE reader_id = ? AND chapter_id = ?`, 
                    [readerId, chapterMasterId], (err, result) => {
                        if (err) {
                            console.error(`Error checking chapter read status for reader ${readerId}:`, err.message);
                            hasErrorOccurred = true;
                        } else {
                            const isRepeatRead = result.times_read > 0;
                            const pointsToAdd = isRepeatRead ? 1 : 5;

                            // Accumulate points for each reader
                            if (!totalPointsForReaders[readerId]) {
                                totalPointsForReaders[readerId] = 0;
                            }
                            totalPointsForReaders[readerId] += pointsToAdd;

                            // Insert chapter record for the reader
                            stmt.run([userId, readerId, chapterMasterId], (err) => {
                                if (err) {
                                    console.error(`Error inserting chapter ${chapterId} for reader ${readerId}:`, err.message);
                                    hasErrorOccurred = true;
                                }

                                pendingOperations--;
                                if (pendingOperations === 0) {
                                    finalizeTransaction();
                                }
                            });
                        }
                    });
                });
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
                return res.status(500).send('Error occurred while recording chapters.');
            }

            // Add accumulated points for each reader
            for (const [readerId, points] of Object.entries(totalPointsForReaders)) {
                await addPoints(readerId, points);
                console.log(`${points} points added for readerId: ${readerId}`);
            }

            // Redirect after all points and chapters are processed
            req.flash('success', 'Chapters marked as read for selected family members.');
            res.redirect(redirectRoute);

            if (typeof callback === 'function') {
                callback(null);
            }
        });
    }
}
app.post('/group-read', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const { bookName, chapter } = req.body;
    const readerIds = req.body['readerIds[]']; // Array of selected reader IDs

    if (!bookName || !chapter || !Array.isArray(readerIds)) {
        req.flash('error', 'Please select a valid book, chapter, and family members.');
        return res.redirect('/group-read');  // Redirect back to the group-read form in case of an error
    }

    const chapterNumber = parseInt(chapter);
    const chapters = [chapterNumber];  // Could be expanded to handle multiple chapters

    // Use the new group read function
    recordGroupRead(userId, readerIds, chapters, bookName, res, req, '/reader-profile', (err) => {
        if (err) {
            console.error('Error recording group read:', err);
            return res.status(500).send('Error marking group read.');
        }

        console.log('Group read successfully recorded.');
    });
});

app.post('/mark-chapter-read', (req, res) => {
    const userId = req.session.userId;
    const readerId = req.session.activeReaderId;
    const bookName = req.body.bookName;
    const chapterNumber = parseInt(req.body.chapter);
    const playbackSpeed = req.body.speed || 1.0; 

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

        const chapterId = row.id;

        // Fetch the next chapter in the plan
        const planSql = `
            SELECT rp.chapter_ids
            FROM reading_plans rp
            JOIN reader_plans rpl ON rpl.plan_id = rp.id
            WHERE rpl.reader_id = ?
        `;

        db.get(planSql, [readerId], (err, plan) => {
            if (err || !plan) {
                console.error('Error retrieving plan:', err ? err.message : 'No plan found');
                return res.redirect('/reader-profile');
            }

            const chapterIds = JSON.parse(plan.chapter_ids);
            const currentChapterIndex = chapterIds.indexOf(chapterId);

            let redirectRoute = '/reader-profile'; // Default redirect
            if (currentChapterIndex < chapterIds.length - 1) {
                const nextChapterId = chapterIds[currentChapterIndex + 1];

                const nextChapterSql = `SELECT book, chapter FROM chaptersmaster WHERE id = ?`;
                db.get(nextChapterSql, [nextChapterId], (err, nextChapter) => {
                    if (err || !nextChapter) {
                        console.error('Error retrieving next chapter:', err.message);
                    } else {
                        // Set the redirect to the next chapter
                        redirectRoute = `/chapter/${nextChapter.book}/${nextChapter.chapter}?autoplay=true&speed=${playbackSpeed}`;
                    }

                    // Call the recordChapters function with the redirect route
                    recordChapters(userId, readerId, [chapterNumber], bookName, res, req, redirectRoute, (err) => {
                        if (err) {
                            console.error('Error recording chapter:', err);
                            return res.status(500).send('Error marking chapter as read.');
                        }
                        console.log('Chapter marked as read and points updated.');
                          // Send response after recordChapters finishes
                    });
                });
            } else {
                // If no more chapters, mark the chapter and redirect to the profile
                recordChapters(userId, readerId, [chapterNumber], bookName, res, req, redirectRoute, (err) => {
                    if (err) {
                        console.error('Error recording chapter:', err);
                        return res.status(500).send('Error marking chapter as read.');
                    }
                    console.log('Chapter marked as read and points updated.');
                      // Send response after recordChapters finishes
                });
            }
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

        // Find the newly added reader's ID
        db.get(findNewReaderSql, [familyId, readerName], (err, row) => {
            if (err) {
                console.error('Error retrieving reader id:', err.message);
                return res.status(500).send('Error retrieving reader id');
            }
            const readerId = row.id;

            // Add an entry for the new reader in the userpoints table with 1 point
            const insertUserPointsSql = `INSERT INTO userpoints (reader_id, user_points) VALUES (?, 1)`;
            db.run(insertUserPointsSql, [readerId], (err) => {
                if (err) {
                    console.error('Error inserting initial points:', err.message);
                    return res.status(500).send('Error inserting initial points');
                }

                console.log(`Inserted 1 point for new reader with ID ${readerId}`);
                res.redirect('/manage');
            });
        });
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
app.get('/about', (req, res) => {
    res.render('about');
});
// app.get('/unread-chapters', (req, res) => {
//     const unreadChaptersSql = `
//         SELECT chaptersmaster.book, chaptersmaster.chapter
//         FROM chaptersmaster
//         LEFT JOIN user_chapters ON chaptersmaster.id = user_chapters.chapter_id
//         WHERE user_chapters.chapter_id IS NULL
//         ORDER BY chaptersmaster.id 
//     `;

//     db.all(unreadChaptersSql, [], (err, unreadRows) => {
//         if (err) {
//             console.error('Error fetching unread chapters:', err.message);
//             return res.status(500).send('Error retrieving unread chapters');
//         }

//         // Group unread chapters by book
//         const unreadChaptersByBook = {};
//         unreadRows.forEach(row => {
//             const book = row.book.trim();
//             if (!unreadChaptersByBook[book]) {
//                 unreadChaptersByBook[book] = [];
//             }
//             unreadChaptersByBook[book].push(row.chapter);
//         });

//         res.render('unread-chapters', { unreadChaptersByBook });
//     });
// });
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
function addPoints(readerId, pointsToAdd, callback) {
    // First, fetch the current points for the reader
    const fetchPointsSql = `SELECT user_points FROM userpoints WHERE reader_id = ?`;

    db.get(fetchPointsSql, [readerId], (err, row) => {
        if (err) {
            console.error("Error fetching current points:", err.message);
            return callback(err); // Pass the error to the callback
        }

        if (row) {
            const currentPoints = row.user_points;
            const newTotalPoints = currentPoints + pointsToAdd;

            // Update the points for the reader
            const updateSql = `UPDATE userpoints SET user_points = ? WHERE reader_id = ?`;

            db.run(updateSql, [newTotalPoints, readerId], (err) => {
                if (err) {
                    console.error("Error updating points:", err.message);
                    return callback(err); // Pass the error to the callback
                }

                console.log(`Updated points for reader ${readerId}. New total: ${newTotalPoints}`);
                
                // Now update the reader's level based on the new total points
                updateReaderLevel(readerId, newTotalPoints, callback); // Pass the callback to updateReaderLevel
            });
        } else {
            console.error("No points found for reader:", readerId);
            return callback(new Error('No points found for reader'));
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
        } else if (level) {
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
            console.log('No level found for the given total points.');
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
        LIMIT 40
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
app.get('/family-leaderboard', (req, res) => {
    // Query to get the top families by total points, summing points of all readers in the family
    const familyLeaderboardSql = `
        SELECT family.family_name, SUM(userpoints.user_points) as total_points
        FROM userpoints
        JOIN readers ON userpoints.reader_id = readers.id
        JOIN family ON readers.family_id = family.id
        GROUP BY family.family_name
        ORDER BY total_points DESC
        LIMIT 25
    `;

    db.all(familyLeaderboardSql, [], (err, rows) => {
        if (err) {
            console.error('Error retrieving family leaderboard:', err.message);
            return res.status(500).send('Error retrieving family leaderboard');
        }

        // Pass the family leaderboard data to the view
        res.render('family-leaderboard', { leaderboard: rows });
    });
});


app.get('/reader-reports/:readerId', (req, res) => {
    const readerId = req.params.readerId;

    // Query to get all chapters reported by this reader
    const reportsSql = `
        SELECT user_chapters.id, chaptersmaster.book, chaptersmaster.chapter, user_chapters.timestamp
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

        // Pass the reports data and readerId to the view
        res.render('reader-reports', { reports, readerId });
    });
});
app.post('/delete-reports/:readerId', (req, res) => {
    const readerId = req.params.readerId;
    let rowIds = req.body['rowIds[]']; // Capture the checkbox values

    // Convert rowIds to an array if it's a single string value
    if (!Array.isArray(rowIds)) {
        rowIds = [rowIds];
    }

    if (!rowIds || rowIds.length === 0) {
        return res.status(400).send('No reports selected for deletion');
    }

    // Call removeChapters, passing rowIds instead of chapterIds
    removeChapters(readerId, rowIds, res, req, `/reader-reports/${readerId}`, (err) => {
        if (err) {
            console.error('Error removing chapters:', err.message);
            return res.status(500).send('Error removing chapters.');
        }
    });
});
app.post('/admin/userpoints/delete/:reader_id', async (req, res) => {
    if (req.session.role !== 'admin') {
        return res.redirect('/');
    } 
    const { reader_id } = req.params;

    try {
        await db.run('DELETE FROM userpoints WHERE reader_id = ?', [reader_id]);
        res.redirect('/admin/userpoints');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

async function removeChapters(readerId, chaptersId, res, req, redirectRoute, callback) {
    const deleteChapterSql = `DELETE FROM user_chapters WHERE id = ?`;
    const stmt = db.prepare(deleteChapterSql);
    let totalPointsToRemove = 0;
    let pendingOperations = chaptersId.length;
    let hasErrorOccurred = false;

    chaptersId.forEach(chapterId => {
        // Check if the chapter is part of a completion cycle by using completion_status
        db.get(`SELECT id, completion_status FROM user_chapters WHERE reader_id = ? AND id = ?`, 
            [readerId, chapterId], 
            (err, row) => {
                if (err) {
                    console.error(`Error finding chapter ${chapterId}:`, err.message);
                    hasErrorOccurred = true;
                } else if (row) {
                    // Reverse points based on completion status
                    totalPointsToRemove += row.completion_status ? 5 : 1;

                    stmt.run([chapterId], (err) => {
                        if (err) {
                            console.error(`Error deleting chapter ${chapterId}:`, err.message);
                            hasErrorOccurred = true;
                        }

                        pendingOperations--;

                        if (pendingOperations === 0) {
                            finalizeTransaction();
                        }
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
                return res.status(500).send('Error removing chapters.');
            }

            if (hasErrorOccurred) {
                console.log('Some errors occurred during the process.');
                return res.status(500).send('Error occurred while removing some chapters.');
            }

            if (totalPointsToRemove > 0) {
                await reversePoints(readerId, totalPointsToRemove);

                const message = `${totalPointsToRemove} points removed for readerId: ${readerId}`;
                req.flash('success', message);
                res.redirect(redirectRoute);
            } else {
                res.redirect(redirectRoute);
            }

            if (typeof callback === 'function') {
                callback(null);
            }
        });
    }
}

function reversePoints(readerId, pointsToSubtract, callback) {
    const updateSql = `UPDATE userpoints SET user_points = user_points - ? WHERE reader_id = ?`;

    db.run(updateSql, [pointsToSubtract, readerId], (err) => {
        if (err) {
            console.error("Error reversing points:", err.message);
            return callback(err); // Pass the error to the callback
        }

        console.log(`Reversed ${pointsToSubtract} points for reader ${readerId}.`);
        
        // After reversing points, fetch the new total points and update the reader's level
        const totalPointsSql = `SELECT user_points FROM userpoints WHERE reader_id = ?`;
        db.get(totalPointsSql, [readerId], (err, row) => {
            if (err) {
                console.error('Error fetching updated total points:', err.message);
                return callback(err);
            }

            const totalPoints = row ? row.user_points : 0;

            // Update the reader's level based on the new total points
            updateReaderLevel(readerId, totalPoints, callback);
        });
    });
}




// Promisify the db.all method
const getUserPoints = () => {
    return new Promise((resolve, reject) => {
        db.all('SELECT * FROM userpoints', (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
};
// Route to get user points
app.get('/admin/userpoints', isAdmin, async (req, res) => {
    try {
        const userpoints = await getUserPoints();
        res.render('admin_userpoints', { userpoints });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});
app.post('/admin/userpoints/edit/:reader_id', async (req, res) => {
    if (req.session.role !== 'admin') {
        return res.redirect('/');
    } 
    const { reader_id } = req.params;
    const { user_points } = req.body;

    try {
        await db.run('UPDATE userpoints SET user_points = ? WHERE reader_id = ?', [user_points, reader_id]);
        res.redirect('/admin/userpoints');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});
app.post('/delete-reports/:readerId', (req, res) => {
    const readerId = req.params.readerId;
    let rowIds = req.body['rowIds[]']; // Capture the checkbox values

    // Convert rowIds to an array if it's a single string value
    if (!Array.isArray(rowIds)) {
        rowIds = [rowIds];
    }

    if (!rowIds || rowIds.length === 0) {
        return res.status(400).send('No reports selected for deletion');
    }

    // Fetch chapter details for flash message
    const fetchChaptersSql = `
        SELECT chaptersmaster.book, chaptersmaster.chapter
        FROM user_chapters
        JOIN chaptersmaster ON user_chapters.chapter_id = chaptersmaster.id
        WHERE user_chapters.id IN (${rowIds.map(() => '?').join(',')})
    `;

    db.all(fetchChaptersSql, rowIds, (err, chapters) => {
        if (err) {
            console.error('Error fetching chapters:', err.message);
            return res.status(500).send('Error fetching chapters');
        }

        // Construct the SQL query to delete the selected rows based on the unique row id
        const deleteSql = `
            DELETE FROM user_chapters
            WHERE id IN (${rowIds.map(() => '?').join(',')})
        `;

        db.run(deleteSql, rowIds, (err) => {
            if (err) {
                console.error('Error deleting reports:', err.message);
                return res.status(500).send('Error deleting reports');
            }

            // Format the deleted chapters for the flash message
            const deletedChapters = chapters.map(chapter => `${chapter.book} ${chapter.chapter}`).join(', ');

            // Set flash message with deleted chapters
            req.flash('success', `Successfully deleted the following chapters: ${deletedChapters}`);

            // Redirect back to the reports page after deletion
            res.redirect(`/reader-reports/${readerId}`);
        });
    });
});

const getReadersInfo = () => {
    return new Promise((resolve, reject) => {
        const query = `
            SELECT 
                readers.id AS reader_id,
                readers.reader_name,
                family.family_name,
                COUNT(user_chapters.id) AS chapters_reported,
                IFNULL(userpoints.user_points, 0) AS total_points,
                levels.level_name AS current_level
            FROM 
                readers
            LEFT JOIN family ON readers.family_id = family.id
            LEFT JOIN user_chapters ON readers.id = user_chapters.reader_id
            LEFT JOIN userpoints ON readers.id = userpoints.reader_id
            LEFT JOIN levels ON readers.current_level_id = levels.id
            GROUP BY 
                readers.id, readers.reader_name, family.family_name, userpoints.user_points, levels.level_name
            ORDER BY readers.id;
        `;
        db.all(query, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
};
app.get('/admin/readers', isAdmin, async (req, res) => {
    try {
        const readers = await getReadersInfo();
        res.render('readers_list', { readers });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});



const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
