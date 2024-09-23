import sqlite3 from 'sqlite3';

const db = new sqlite3.Database('../mydatabase.db');

// Function to add a new reading plan
export function addReadingPlan(nameOfPlan, chaptersToAdd, callback) {
    const insertPlanSql = `
        INSERT INTO reading_plans (name, chapter_ids)
        VALUES (?, ?)
    `;

    const chaptersJson = JSON.stringify(chaptersToAdd);

    db.run(insertPlanSql, [nameOfPlan, chaptersJson], function (err) {
        if (err) {
            console.error('Error adding reading plan:', err.message);
            if (callback) callback(err);
        } else {
            console.log(`Reading plan '${nameOfPlan}' added with ID ${this.lastID}`);
            if (callback) callback(null, this.lastID);
        }
    });

    db.close();
}
