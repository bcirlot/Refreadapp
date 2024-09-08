
//for test data in the family and readers tables

const sqlite3 = require('sqlite3').verbose();

let db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error(err.message);
        return;
    }
    console.log('Connected to the mydatabase.db database.');
    fillReadersTable();
    fillFamiliesTable();
});


function fillFamiliesTable() {
    const families = [
        { user_id: 1, family_name: 'Smith' },
        { user_id: 2, family_name: 'Johnson' },
        { user_id: 3, family_name: 'Williams' }
    ];

    families.forEach(family => {
        db.run(`INSERT INTO family (user_id, family_name) VALUES (?, ?)`, [family.user_id, family.family_name], (err) => {
            if (err) {
                console.error(`Error inserting into family table: ${err.message}`);
            } else {
                console.log(`Inserted family: ${family.family_name}`);
            }
        });
    });
}

// Function to fill the readers table with test data
function fillReadersTable() {
    const readers = [
        { family_id: 1, reader_name: 'John Smith' },
        { family_id: 1, reader_name: 'Emily Smith' },
        { family_id: 2, reader_name: 'Michael Johnson' },
        { family_id: 2, reader_name: 'Sarah Johnson' },
        { family_id: 3, reader_name: 'Chris Williams' }
    ];

    readers.forEach(reader => {
        db.run(`INSERT INTO readers (family_id, reader_name) VALUES (?, ?)`, [reader.family_id, reader.reader_name], (err) => {
            if (err) {
                console.error(`Error inserting into readers table: ${err.message}`);
            } else {
                console.log(`Inserted reader: ${reader.reader_name}`);
            }
        });
    });
}