const sql = require('mysql2');
const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const methodOverride = require('method-override');

const app = express();
const port = 3000;

const db = sql.createConnection({
	host: 'localhost',
	user: 'root',
	password: '',
	database: 'PAP'
});

db.connect((err) => {
	if (err) {
		console.error("Error connecting to MYSQL:", err.stack);
		return;
	}
	console.log("Connected to MySQL");
});

app.use(session({
	secret: 'pap1234',
	resave: false,
	saveUninitialized: false
}));

app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', [path.join(__dirname, 'views'), path.join(__dirname, 'private')]);

app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));

app.listen(port, () => {
	console.log(`Server running: http://localhost:${port}`);
});

app.get('/', (req, res) => {
	res.render('login', { error: null });
});

app.get('/register', (req, res) => {
	res.render('register', { error: null });
});

app.post('/login', (req, res) => {
	const { Username, Password } = req.body;

	if (!Username || !Password) {
		return res.status(400).render('login', { error: "Please fill the Username and Password" });
	}

	const query = "SELECT * FROM users WHERE Username = ? LIMIT 1";

	db.query(query, [Username], async (err, results) => {
		if (err) {
			console.error("DB error:", err);
			return res.status(500).render('login', { error: "Server error" });
		}

		if (results.length === 0) {
			return res.status(401).render('login', { error: "Invalid Credentials" });
		}

		try {
			const user = results[0];
			const match = await bcrypt.compare(Password, user.Password);

			if (!match) {
				return res.status(401).render('login', { error: "Invalid Credentials" });
			}

			req.session.user = { Username: user.Username, Role: user.Role };

			logActivity(user.ID, 'LOGIN', `User ${user.Username} logged in`);

			if (user.Role === 'admin') {
				return res.redirect('/admin');
			}

			res.redirect('/index');
		} catch (compareErr) {
			console.error("Compare error:", compareErr);
			res.status(500).render('login', { error: "Server error" });
		}
	});
});

app.post('/register', async (req, res) => {
	try {
		const { Username, Email, Password } = req.body;

		if (!Username || !Email || !Password) {
			return res.status(400).send("Please provide all required fields");
		}

		const [existingUsers] = await db.promise().query(
			"SELECT * FROM users WHERE Username = ? OR Email = ?",
			[Username, Email]
		);

		if (existingUsers.length > 0) {
			return res.status(409).send("Username or email already exists");
		}

		const hashedPassword = await bcrypt.hash(Password, 10);
		const role = Username.toLowerCase() === 'admin' ? 'admin' : 'user';

		const [result] = await db.promise().query(
			"INSERT INTO users (Username, Email, Password, `Role`, `Registration Date`) VALUES (?, ?, ?, ?, NOW())",
			[Username, Email, hashedPassword, role]
		);

		logActivity(result.insertId, 'REGISTER', `User ${Username} registered`);

		res.redirect('/');
	} catch (error) {
		console.error("Error in register route:", error);
		res.status(500).send("Server error");
	}
});

app.get('/index', (req, res) => {
	if (!req.session.user) {
		return res.redirect('/');
	}

	const user = req.session.user;

	db.query('SELECT * FROM categories', (catErr, catResults) => {
		if (catErr) {
		console.error(catErr);
		return res.status(500).send('Database error loading categories');
		}

		db.query('SELECT * FROM products', (prodErr, prodResults) => {
		if (prodErr) {
			console.error(prodErr);
			return res.status(500).send('Database error loading products');
		}

		const products = prodResults.map(prod => ({
			...prod,
			price: prod.Price ? parseFloat(prod.Price) : null
		}));

		res.render('index', {
			user,
			products,
			categories: catResults,
			welcomeText: `Welcome, ${user.Username}`
		});
		});  
	});  
});  

app.get('/category/:id', (req, res) => {
	if (!req.session.user) {
		return res.redirect('/');
	}

	const categoryId = parseInt(req.params.id, 10);
	if (isNaN(categoryId)) {
		return res.status(400).send('Invalid category ID');
	}

	db.query('SELECT * FROM categories', (catErr, catResults) => {
		if (catErr) {
		console.error(catErr);
		return res.status(500).send('Database error loading categories');
		}

		db.query('SELECT * FROM categories WHERE ID = ?', [categoryId], (selCatErr, selCatResults) => {
		if (selCatErr) {
			console.error(selCatErr);
			return res.status(500).send('Database error loading category');
		}
		if (selCatResults.length === 0) {
			return res.status(404).send('Category not found');
		}
		const category = selCatResults[0];

		db.query('SELECT * FROM products WHERE CategoryID = ?', [categoryId], (prodErr, prodResults) => {
			if (prodErr) {
			console.error(prodErr);
			return res.status(500).send('Database error loading products');
			}

			const products = prodResults.map(prod => ({
			...prod,
			price: prod.Price ? parseFloat(prod.Price) : null
			}));

			res.render('category', {
			user: req.session.user,
			categories: catResults,
			category,
			products,
			welcomeText: `${category.Name}`
			});
		});
		});
	});
});

app.get('/sell', (req, res) => {
	if (!req.session.user) {
		return res.redirect('/');
	}

	db.query('SELECT * FROM categories', (err, results) => {
		if (err) return res.status(500).send('DB error fetching categories');
		
		res.render('sell', {
			user: req.session.user,
			categories: results
		});
	});
});

app.post('/sell', (req, res) => {
	if (!req.session.user) {
		return res.redirect('/');
	}

	const { name, price, description, categoryID } = req.body;
	const publisherID = req.session.user.ID;

	if (!name || !price || !categoryID) {
		return res.status(400).send('Missing required fields');
	}

	db.query(
		'INSERT INTO products (Name, Price, Description, CategoryID, PublisherID) VALUES (?, ?, ?, ?, ?)',
		[name, price, description, categoryID, publisherID],
		(err) => {
			if (err) return res.status(500).send('DB error adding product');
			res.redirect(`/category/${category}`); 
		}
	);
});

app.get('/admin', async (req, res) => {
	if (!req.session.user || req.session.user.Role !== 'admin') {
		return res.redirect('/');
	}

	try {
		
		const [rows] = await db.promise().query(`
			SELECT DATE(Timestamp) as loginDate, COUNT(*) as count
			FROM activity_logs
			WHERE Action = 'LOGIN'
			GROUP BY DATE(Timestamp)
			ORDER BY DATE(Timestamp)
		`);

		const loginsPerDay = rows.map(row => ({
			date: row.loginDate.toISOString().split('T')[0],
			count: row.count
		}));

		const [userCountResult] = await db.promise().query("SELECT COUNT(*) AS total FROM users");
		const totalUsers = userCountResult[0].total;

		const [users] = await db.promise().query(
			"SELECT ID, Username, Email, Role FROM users ORDER BY Username"
		);

		const [activeTodayRows] = await db.promise().query(`
			SELECT COUNT(DISTINCT UserID) as activeUsersToday
			FROM activity_logs
			WHERE Action = 'LOGIN'
			AND DATE(Timestamp) = CURDATE()
		`);

		const activeUsersToday = activeTodayRows[0].activeUsersToday || 0;

		res.render('admin', {
			user: req.session.user,
			loginsPerDay,
			users,
			totalUsers,
			activeUsersToday
		});
	} catch (error) {
		console.error("Erro ao buscar dados de login por dia:", error);
		res.status(500).send("Erro no servidor");
	}
});

app.get('/admin/users', async (req, res) => {
	if (!req.session.user || req.session.user.Role !== 'admin') {
		return res.redirect('/');
	}

	const search = req.query.search || '';
	const role = req.query.role || '';
	const sort = req.query.sort || 'Username';
	const order = req.query.order || 'ASC';
	const success = req.query.success === '1' ? true : false;
	const page = parseInt(req.query.page) || 1;
	const pageSize = 10; 

	try {
		let whereClauses = [];
		let params = [];

		if (search) {
			whereClauses.push("(Username LIKE ? OR Email LIKE ?)");
			params.push(`%${search}%`, `%${search}%`);
		}

		if (role) {
			whereClauses.push("Role = ?");
			params.push(role);
		}

		const whereSql = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';

		const countQuery = `SELECT COUNT(*) as total FROM users ${whereSql}`;
		const [countRows] = await db.promise().query(countQuery, params);
		const totalUsers = countRows[0].total;

		const totalPages = Math.ceil(totalUsers / pageSize);
		const currentPage = Math.min(Math.max(page, 1), totalPages || 1);

		const allowedSortFields = ['Username', 'Email', 'Role', 'Registration Date'];
		const allowedOrder = ['ASC', 'DESC'];

		const sortField = allowedSortFields.includes(sort) ? sort : 'Username';
		const sortOrder = allowedOrder.includes(order.toUpperCase()) ? order.toUpperCase() : 'ASC';

		const offset = (currentPage - 1) * pageSize;

		const dataQuery = `
			SELECT ID, Username, Email, Role, \`Registration Date\`
			FROM users
			${whereSql}
			ORDER BY \`${sortField}\` ${sortOrder}
			LIMIT ? OFFSET ?
		`;

		const dataParams = [...params, pageSize, offset];

		const [users] = await db.promise().query(dataQuery, dataParams);

		res.render('user-management', {
			users,
			search,
			role,
			sort: sortField,
			order: sortOrder,
			success,
			totalPages,
			currentPage
		});
	} catch (error) {
		console.error("Error fetching users:", error);
		res.status(500).send("Server error");
	}
});

app.get('/admin/users/:id/edit', (req, res) => {
	if (!req.session.user || req.session.user.Role !== 'admin') {
		return res.redirect('/');
	}

	const userId = req.params.id;
	const query = "SELECT ID, Username, Email, Role FROM users WHERE ID = ? LIMIT 1";

	db.query(query, [userId], (err, results) => {
		if (err || results.length === 0) {
			console.error("DB error or user not found:", err);
			return res.status(404).send("User not found");
		}
		res.render('edit-user', { user: results[0], error: null });
	});
});

app.post('/admin/users/:id/edit', async (req, res) => {
	if (!req.session.user || req.session.user.Role !== 'admin') {
		return res.redirect('/');
	}

	const userId = req.params.id;
	const { Username, Email, Role } = req.body;

	if (!Username || !Email || !Role) {
		return res.status(400).send("Please fill all fields");
	}

	try {
		const [existing] = await db.promise().query(
			"SELECT * FROM users WHERE (Username = ? OR Email = ?) AND ID != ?",
			[Username, Email, userId]
		);

		if (existing.length > 0) {
			return res.status(409).send("Username or email already in use by another user");
		}

		await db.promise().query(
			"UPDATE users SET Username = ?, Email = ?, Role = ? WHERE ID = ?",
			[Username, Email, Role, userId]
		);

		logActivity(userId, 'UPDATE_USER', `User ${Username} updated`);

		res.redirect('/admin/users?success=1');
	} catch (err) {
		console.error("DB update error:", err);
		res.status(500).send("Server error");
	}
});

app.delete('/admin/users/:id', (req, res) => {
	if (!req.session.user || req.session.user.Role !== 'admin') {
		return res.redirect('/');
	}

	const userId = req.params.id;

	db.query("SELECT Username FROM users WHERE ID = ?", [userId], (err, results) => {
		if (err || results.length === 0) {
			console.error("User not found before delete:", err);
			return res.status(404).send("User not found");
		}

		const username = results[0].Username;

		db.query("DELETE FROM users WHERE ID = ?", [userId], (err) => {
			if (err) {
				console.error("Delete error:", err);
				return res.status(500).send("Server error");
			}

			logActivity(userId, 'DELETE_USER', `User ${username} deleted`);

			res.redirect('/admin/users');
		});
	});
});

app.get('/admin/products', (req, res) => {
	if (!req.session.user) {
		return res.redirect('/');
	}

	const search = req.query.search || '';
	const category = req.query.category || '';
	const sort = req.query.sort || 'ID';
	const order = req.query.order || 'ASC';
	const page = parseInt(req.query.page) || 1;
	const limit = 10;
	const offset = (page - 1) * limit;

	let whereClause = 'WHERE 1=1';
	const params = [];

	if (search) {
		whereClause += ' AND (Name LIKE ? OR Description LIKE ?)';
		params.push(`%${search}%`, `%${search}%`);
	}

	if (category) {
		whereClause += ' AND CategoryID = ?';
		params.push(category);
	}

	const queryCount = `SELECT COUNT(*) as count FROM products ${whereClause}`;
	const queryProducts = `
		SELECT p.*, c.Name AS CategoryName
		FROM products p
		LEFT JOIN categories c ON p.CategoryID = c.ID
		${whereClause}
		ORDER BY ${sort} ${order}
		LIMIT ? OFFSET ?
	`;

	params.push(limit, offset);

	db.query('SELECT ID, Name FROM categories', (err, categories) => {
		if (err) {
			console.error('Error loading categories:', err);
			return res.status(500).send('Error loading categories');
		}

		db.query(queryCount, params.slice(0, -2), (err, countResult) => {
			if (err) {
				console.error(err);
				return res.status(500).send('Error counting products');
			}

			const totalItems = countResult[0].count;
			const totalPages = Math.ceil(totalItems / limit);

			db.query(queryProducts, params, (err, products) => {
				if (err) {
					console.error(err);
					return res.status(500).send('Error loading products');
				}

				const productsWithParsedPrice = products.map(prod => ({
					...prod,
					Price: prod.Price !== null && prod.Price !== undefined ? parseFloat(prod.Price) : null
				}));

				res.render('product-management', {
					user: req.session.user,
					products: productsWithParsedPrice,
					categories,
					category,
					search,
					sort,
					order,
					currentPage: page,
					totalPages,
					success: req.query.success === '1'
				});
			});
		});
	});
});

app.get('/admin/products/edit/:id', (req, res) => {
	if (!req.session.user) {
		return res.redirect('/');
	}	

	const id = parseInt(req.params.id, 10);
	if (isNaN(id)) return res.status(400).send('Invalid product ID');

	db.query('SELECT * FROM products WHERE ID = ?', [id], (err, results) => {
		if (err) return res.status(500).send('DB error');
		if (results.length === 0) return res.status(404).send('Product not found');

		const product = results[0];

		db.query('SELECT ID, Name FROM categories', (err, categories) => {
			if (err) return res.status(500).send('Error loading categories');

			res.render('product-edit', {
				user: req.session.user,
				product,
				categories,  
				error: null
			});
		});
	});
});


app.post('/admin/products/edit/:id', (req, res) => {
	if (!req.session.user) return res.redirect('/');

	const id = parseInt(req.params.id, 10);
	const { Name, Price, Description, CategoryID, PublisherID } = req.body;

	if (isNaN(id)) return res.status(400).send('Invalid product ID');

	db.query(
		'UPDATE products SET Name=?, Price=?, Description=?, CategoryID=?, PublisherID=? WHERE ID=?',
		[Name, Price, Description, CategoryID, PublisherID, id],
		err => {
		if (err) return res.status(500).send('Error updating product');
		res.redirect('/admin/products?success=1');
		}
	);
});

app.post('/admin/products/delete/:id', (req, res) => {
	if (!req.session.user) return res.redirect('/');

	const id = parseInt(req.params.id, 10);
	if (isNaN(id)) return res.status(400).send('Invalid product ID');

	db.query('DELETE FROM products WHERE ID=?', [id], err => {
		if (err) return res.status(500).send('Error deleting product');
		res.redirect('/admin/products');
	});
});


async function logActivity(userId, action, details = '') {
	try {
		await db.promise().query(
		"INSERT INTO activity_logs (UserID, Action, Details) VALUES (?, ?, ?)",
		[userId, action, details]
		);
	} catch (error) {
		console.error("Error logging activity:", error);
	}
}

app.get('/logout', (req, res) => {
	if (req.session.user && req.session.user.Username) {
		const userIdQuery = "SELECT ID FROM users WHERE Username = ? LIMIT 1";
		db.query(userIdQuery, [req.session.user.Username], (err, results) => {
			if (!err && results.length > 0) {
				logActivity(results[0].ID, 'LOGOUT', `User ${req.session.user.Username} logged out`);
			}
			req.session.destroy(() => {
				res.redirect('/');
			});
		});
	} else {
		req.session.destroy(() => {
			res.redirect('/');
		});
	}
});

app.get('/admin/activity-logs', async (req, res) => {
	if (!req.session.user || req.session.user.Role !== 'admin') {
		return res.redirect('/');
	}

	const userIdFilter = req.query.userId || '';
	const actionFilter = req.query.action || '';
	const page = parseInt(req.query.page) || 1;
	const pageSize = 25;

	try {
		let whereClauses = [];
		let params = [];

		if (userIdFilter) {
		whereClauses.push('UserID = ?');
		params.push(userIdFilter);
		}

		if (actionFilter) {
		whereClauses.push('Action LIKE ?');
		params.push(`%${actionFilter}%`);
		}

		const whereSql = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';

		const countQuery = `SELECT COUNT(*) as total FROM activity_logs ${whereSql}`;
		const [countRows] = await db.promise().query(countQuery, params);
		const totalLogs = countRows[0].total;
		const totalPages = Math.ceil(totalLogs / pageSize);

		const currentPage = Math.min(Math.max(page, 1), totalPages || 1);
		const offset = (currentPage - 1) * pageSize;

		const logsQuery = `
		SELECT al.ID, al.UserID, al.Action, al.Timestamp, al.Details, u.Username
		FROM activity_logs al
		LEFT JOIN users u ON al.UserID = u.ID
		${whereSql}
		ORDER BY al.Timestamp DESC
		LIMIT ? OFFSET ?
		`;

		const logsParams = [...params, pageSize, offset];
		const [logs] = await db.promise().query(logsQuery, logsParams);

		const [users] = await db.promise().query("SELECT ID, Username FROM users ORDER BY Username");

		res.render('activity-logs', {
		logs,
		users,
		userIdFilter,
		actionFilter,
		totalPages,
		currentPage
		});
	} catch (error) {
		console.error("Error fetching activity logs:", error);
		res.status(500).send("Server error");
	}
});

app.post('/admin/activity-logs/clear', async (req, res) => {
	if (!req.session.user || req.session.user.Role !== 'admin') {
		console.log("Blocked: user not admin");
		return res.redirect('/');
	}

	try {
		const [result] = await db.promise().query("DELETE FROM activity_logs");
		console.log("Activity logs cleared:", result);
		res.redirect('/admin/activity-logs');
	} catch (error) {
		console.error("Error clearing logs:", error);
		res.status(500).send("Error clearing activity logs");
	}
});

app.get('/session-info', (req, res) => {
	res.json(req.session.user || 'No session user');
});