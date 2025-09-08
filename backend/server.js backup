const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Database connection
const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

// Test database connection
pool.execute('SELECT 1').then(() => {
  console.log('Database connection successful');
}).catch(err => {
  console.error('Database connection failed:', err);
});

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Admin Middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }
  next();
};

// AUTH ENDPOINTS
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );
    
    if (users.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    // Update last login
    await pool.execute(
      'UPDATE users SET last_login = NOW() WHERE id = ?',
      [user.id]
    );
    
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          name: user.name,
          role: user.role,
          postsCount: user.posts_count,
          lastLogin: user.last_login,
          createdAt: user.created_at
        },
        token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

app.post('/api/auth/register', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { username, name, password, role = 'user' } = req.body;
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const [result] = await pool.execute(
      'INSERT INTO users (username, name, password_hash, role) VALUES (?, ?, ?, ?)',
      [username, name, hashedPassword, role]
    );
    
    res.json({
      success: true,
      data: { id: result.insertId, username, name, role }
    });
  } catch (error) {
    console.error('Register error:', error);
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ success: false, error: 'Username already exists' });
    } else {
      res.status(500).json({ success: false, error: 'Registration failed' });
    }
  }
});

// KORRIGIERTER CHANGE PASSWORD ENDPOINT MIT TRANSAKTIONEN
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const { currentPassword, newPassword, userId, isAdmin } = req.body;
    
    console.log('=== CHANGE PASSWORD DEBUG ===');
    console.log('Change password request:', { 
      userId, 
      isAdmin, 
      hasCurrentPassword: !!currentPassword,
      requestingUserId: req.user.id,
      requestingUserRole: req.user.role 
    });
    
    // Validierung
    if (!newPassword) {
      return res.status(400).json({ success: false, error: 'New password is required' });
    }
    
    // Bestimme den Ziel-Benutzer
    let targetUserId;
    let requireCurrentPassword = true;
    
    if (isAdmin && req.user.role === 'admin' && userId) {
      // Admin ändert Passwort eines anderen Benutzers
      targetUserId = parseInt(userId);
      requireCurrentPassword = false;
      console.log('Admin changing password for user:', targetUserId);
    } else {
      // Benutzer ändert sein eigenes Passwort
      targetUserId = req.user.id;
      requireCurrentPassword = true;
      console.log('User changing own password:', targetUserId);
    }
    
    // Start Transaction
    await connection.beginTransaction();
    console.log('Transaction started');
    
    // Hole Ziel-Benutzer aus der Datenbank
    const [users] = await connection.execute(
      'SELECT * FROM users WHERE id = ?',
      [targetUserId]
    );
    
    if (users.length === 0) {
      await connection.rollback();
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    const targetUser = users[0];
    console.log('Target user found:', { id: targetUser.id, username: targetUser.username });
    console.log('Current password hash length:', targetUser.password_hash ? targetUser.password_hash.length : 'null');
    
    // Überprüfe aktuelles Passwort nur wenn erforderlich
    if (requireCurrentPassword) {
      if (!currentPassword) {
        await connection.rollback();
        return res.status(400).json({ success: false, error: 'Current password is required' });
      }
      
      const validPassword = await bcrypt.compare(currentPassword, targetUser.password_hash);
      console.log('Current password validation result:', validPassword);
      
      if (!validPassword) {
        await connection.rollback();
        return res.status(400).json({ success: false, error: 'Current password is incorrect' });
      }
    }
    
    // Hash neues Passwort
    console.log('Hashing new password...');
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    console.log('New password hashed successfully, length:', hashedPassword.length);
    console.log('New hash starts with:', hashedPassword.substring(0, 20) + '...');
    
    // Update Passwort mit expliziter Transaktion
    console.log('Updating password in database...');
    const [updateResult] = await connection.execute(
      'UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?',
      [hashedPassword, targetUserId]
    );
    
    console.log('Update result:', updateResult);
    console.log('Affected rows:', updateResult.affectedRows);
    console.log('Changed rows:', updateResult.changedRows);
    
    if (updateResult.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({ success: false, error: 'User not found or password not updated' });
    }
    
    // Verify the update by reading back the user
    console.log('Verifying password update...');
    const [verifyUsers] = await connection.execute(
      'SELECT id, username, password_hash, updated_at FROM users WHERE id = ?',
      [targetUserId]
    );
    
    if (verifyUsers.length > 0) {
      const verifiedUser = verifyUsers[0];
      console.log('Verified user after update:');
      console.log('- ID:', verifiedUser.id);
      console.log('- Username:', verifiedUser.username);
      console.log('- Password hash length:', verifiedUser.password_hash.length);
      console.log('- Updated at:', verifiedUser.updated_at);
      console.log('- Hash starts with:', verifiedUser.password_hash.substring(0, 20) + '...');
      
      // Test if the new password works
      const testNewPassword = await bcrypt.compare(newPassword, verifiedUser.password_hash);
      console.log('New password verification test:', testNewPassword);
      
      if (!testNewPassword) {
        await connection.rollback();
        return res.status(500).json({ success: false, error: 'Password hash verification failed after update' });
      }
    }
    
    // Commit the transaction
    await connection.commit();
    console.log('Transaction committed successfully');
    
    console.log('Password updated successfully for user:', targetUserId);
    
    res.json({ 
      success: true, 
      data: { 
        message: isAdmin && targetUserId !== req.user.id 
          ? 'User password updated successfully' 
          : 'Password updated successfully',
        userId: targetUserId,
        updatedAt: new Date().toISOString()
      } 
    });
  } catch (error) {
    // Rollback on any error
    try {
      await connection.rollback();
      console.log('Transaction rolled back due to error');
    } catch (rollbackError) {
      console.error('Rollback error:', rollbackError);
    }
    
    console.error('Change password error:', error);
    console.error('Error details:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({ success: false, error: 'Failed to change password: ' + error.message });
  } finally {
    // Always release the connection
    connection.release();
    console.log('Database connection released');
  }
});

// LEARNING FIELDS ENDPOINTS
app.get('/api/learning-fields', authenticateToken, async (req, res) => {
  try {
    const [fields] = await pool.execute(`
      SELECT lf.*, u.username as created_by_username,
             COALESCE(post_counts.post_count, 0) as postsCount,
             COALESCE(student_counts.student_count, 0) as studentsCount
      FROM learning_fields lf 
      LEFT JOIN users u ON lf.created_by = u.id
      LEFT JOIN (
        SELECT learning_field_id, COUNT(*) as post_count 
        FROM posts 
        WHERE status = 'approved' 
        GROUP BY learning_field_id
      ) post_counts ON lf.id = post_counts.learning_field_id
      LEFT JOIN (
        SELECT COUNT(DISTINCT author_id) as student_count
        FROM posts 
        WHERE status = 'approved'
      ) student_counts ON 1=1
      ORDER BY lf.created_at DESC
    `);
    
    res.json({ success: true, data: fields });
  } catch (error) {
    console.error('Get learning fields error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch learning fields' });
  }
});

app.get('/api/learning-fields/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [fields] = await pool.execute(`
      SELECT lf.*, u.username as created_by_username,
             COALESCE(post_counts.post_count, 0) as postsCount,
             COALESCE(student_counts.student_count, 0) as studentsCount
      FROM learning_fields lf 
      LEFT JOIN users u ON lf.created_by = u.id
      LEFT JOIN (
        SELECT learning_field_id, COUNT(*) as post_count 
        FROM posts 
        WHERE status = 'approved' AND learning_field_id = ?
        GROUP BY learning_field_id
      ) post_counts ON lf.id = post_counts.learning_field_id
      LEFT JOIN (
        SELECT COUNT(DISTINCT author_id) as student_count
        FROM posts 
        WHERE status = 'approved' AND learning_field_id = ?
      ) student_counts ON 1=1
      WHERE lf.id = ?
    `, [id, id, id]);
    
    if (fields.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Lernfeld nicht gefunden' 
      });
    }
    
    res.json({ success: true, data: fields });
  } catch (error) {
    console.error('Get learning field error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch learning field' });
  }
});

app.post('/api/learning-fields', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('=== CREATE LEARNING FIELD DEBUG ===');
    console.log('User:', req.user);
    console.log('Request body:', req.body);
    
    const { title, description, color = 'from-primary to-primary-glow' } = req.body;
    
    if (!title || !title.trim()) {
      console.log('Title validation failed');
      return res.status(400).json({ success: false, error: 'Title is required' });
    }
    
    if (!description || !description.trim()) {
      console.log('Description validation failed');
      return res.status(400).json({ success: false, error: 'Description is required' });
    }
    
    console.log('Inserting learning field:', { 
      title: title.trim(), 
      description: description.trim(), 
      color, 
      created_by: req.user.id 
    });
    
    const [result] = await pool.execute(
      'INSERT INTO learning_fields (title, description, color, created_by, created_at) VALUES (?, ?, ?, ?, NOW())',
      [title.trim(), description.trim(), color, req.user.id]
    );
    
    console.log('Learning field created successfully:', result.insertId);
    
    res.json({
      success: true,
      data: { 
        id: result.insertId, 
        title: title.trim(), 
        description: description.trim(), 
        color,
        postsCount: 0,
        studentsCount: 0,
        created_by: req.user.id,
        created_by_username: req.user.username
      }
    });
  } catch (error) {
    console.error('Create learning field error:', error);
    console.error('Error details:', error.message);
    console.error('Error code:', error.code);
    console.error('Error stack:', error.stack);
    res.status(500).json({ success: false, error: 'Failed to create learning field: ' + error.message });
  }
});

app.delete('/api/learning-fields/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.execute('DELETE FROM learning_fields WHERE id = ?', [req.params.id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, error: 'Learning field not found' });
    }
    
    res.json({ success: true, data: { deleted: true } });
  } catch (error) {
    console.error('Delete learning field error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete learning field' });
  }
});

// POSTS ENDPOINTS
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { learningFieldId, status } = req.query;
    
    let query = `
      SELECT p.*, u.username as author_username, u.name as author_name, 
             lf.title as learning_field_title
      FROM posts p
      JOIN users u ON p.author_id = u.id
      JOIN learning_fields lf ON p.learning_field_id = lf.id
    `;
    
    const params = [];
    const conditions = [];
    
    if (learningFieldId) {
      conditions.push('p.learning_field_id = ?');
      params.push(learningFieldId);
    }
    
    if (status) {
      conditions.push('p.status = ?');
      params.push(status);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY p.created_at DESC';
    
    const [posts] = await pool.execute(query, params);
    res.json({ success: true, data: posts });
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch posts' });
  }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content, learningFieldId, hasImages = false, hasTerminal = false, hasNotes = false, notes = null } = req.body;
    
    console.log('Creating post - Request body:', req.body);
    console.log('User ID:', req.user.id);
    
    // Validierung
    if (!title || !title.trim()) {
      return res.status(400).json({ success: false, error: 'Title is required' });
    }
    
    if (!content || !content.trim()) {
      return res.status(400).json({ success: false, error: 'Content is required' });
    }
    
    if (!learningFieldId) {
      return res.status(400).json({ success: false, error: 'Learning field ID is required' });
    }
    
    // undefined zu null konvertieren für MySQL + saubere Parameter
    const cleanParams = [
      title.trim(),
      content.trim(),
      req.user.id,
      parseInt(learningFieldId) || null,
      hasImages ? 1 : 0,
      hasTerminal ? 1 : 0,
      hasNotes ? 1 : 0,
      notes && notes.trim() ? notes.trim() : null
    ];
    
    console.log('Clean parameters:', cleanParams);
    
    const [result] = await pool.execute(
      'INSERT INTO posts (title, content, author_id, learning_field_id, has_images, has_terminal, has_notes, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      cleanParams
    );
    
    console.log('Post created successfully:', result.insertId);
    
    // Frontend erwartet Array-Format für Konsistenz
    const newPost = {
      id: result.insertId,
      title: title.trim(),
      content: content.trim(),
      status: 'pending',
      authorName: req.user.username,
      createdAt: new Date().toISOString(),
      hasImages: hasImages,
      hasTerminal: hasTerminal,
      hasNotes: hasNotes,
      notes: notes
    };
    
    res.json({
      success: true,
      data: [newPost] // Array statt einzelnes Objekt
    });
  } catch (error) {
    console.error('Create post error:', error);
    console.error('Error details:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({ success: false, error: 'Failed to create post' });
  }
});

app.put('/api/posts/:id/approve', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await pool.execute(
      'UPDATE posts SET status = "approved" WHERE id = ?',
      [req.params.id]
    );
    
    res.json({ success: true, data: { status: 'approved' } });
  } catch (error) {
    console.error('Approve post error:', error);
    res.status(500).json({ success: false, error: 'Failed to approve post' });
  }
});

app.put('/api/posts/:id/reject', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await pool.execute(
      'UPDATE posts SET status = "rejected" WHERE id = ?',
      [req.params.id]
    );
    
    res.json({ success: true, data: { status: 'rejected' } });
  } catch (error) {
    console.error('Reject post error:', error);
    res.status(500).json({ success: false, error: 'Failed to reject post' });
  }
});

app.delete('/api/posts/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await pool.execute('DELETE FROM posts WHERE id = ?', [req.params.id]);
    
    // Frontend erwartet Array-Format für Konsistenz
    res.json({ success: true, data: [{ deleted: true }] });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete post' });
  }
});

// EXERCISES ENDPOINTS - Jetzt mit Approval-System für normale User
app.get('/api/exercises', authenticateToken, async (req, res) => {
  try {
    const { learningFieldId, status } = req.query;
    
    let query = `
      SELECT e.*, u.username as created_by_username, u.name as created_by_name,
             lf.title as learning_field_title
      FROM exercises e
      JOIN users u ON e.created_by = u.id
      JOIN learning_fields lf ON e.learning_field_id = lf.id
    `;
    
    const params = [];
    const conditions = [];
    
    if (learningFieldId) {
      conditions.push('e.learning_field_id = ?');
      params.push(learningFieldId);
    }
    
    if (status) {
      conditions.push('e.status = ?');
      params.push(status);
    } else {
      // Normale User sehen nur approved exercises, Admins sehen alle
      if (req.user.role !== 'admin') {
        conditions.push('e.status = "approved"');
      }
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY e.created_at DESC';
    
    const [exercises] = await pool.execute(query, params);
    
    // Parse JSON content for each exercise
    const processedExercises = exercises.map(exercise => ({
      ...exercise,
      content: exercise.content ? JSON.parse(exercise.content) : {}
    }));
    
    res.json({ success: true, data: processedExercises });
  } catch (error) {
    console.error('Get exercises error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch exercises' });
  }
});

// Alle User können Übungen erstellen, aber sie werden auf "pending" gesetzt
app.post('/api/exercises', authenticateToken, async (req, res) => {
  try {
    const { 
      learning_field_id, 
      title, 
      description, 
      type, 
      points, 
      content 
    } = req.body;
    
    console.log('Creating exercise - Request body:', req.body);
    console.log('User role:', req.user.role);
    
    // Validierung
    if (!title || !title.trim()) {
      return res.status(400).json({ success: false, error: 'Title is required' });
    }
    
    if (!learning_field_id) {
      return res.status(400).json({ success: false, error: 'Learning field ID is required' });
    }
    
    if (!type) {
      return res.status(400).json({ success: false, error: 'Exercise type is required' });
    }
    
    // Status: Admin-erstellte Übungen sind sofort approved, User-Übungen pending
    const status = req.user.role === 'admin' ? 'approved' : 'pending';
    
    const cleanParams = [
      title.trim(),
      description && description.trim() ? description.trim() : null,
      type,
      points || 1,
      status,
      JSON.stringify(content || {}),
      parseInt(learning_field_id) || null,
      req.user.id
    ];
    
    const [result] = await pool.execute(
      'INSERT INTO exercises (title, description, type, points, status, content, learning_field_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())',
      cleanParams
    );
    
    console.log('Exercise created successfully:', result.insertId, 'Status:', status);
    
    const newExercise = {
      id: result.insertId,
      title: title.trim(),
      description: description || null,
      type: type,
      points: points || 1,
      content: content || {},
      status: status,
      createdAt: new Date().toISOString()
    };
    
    res.json({
      success: true,
      data: [newExercise]
    });
  } catch (error) {
    console.error('Create exercise error:', error);
    console.error('Error details:', error.message);
    res.status(500).json({ success: false, error: 'Failed to create exercise' });
  }
});

// Neue Endpoints für Exercise Approval (nur Admin)
app.get('/api/exercises/pending', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [exercises] = await pool.execute(`
      SELECT e.*, u.username as created_by_username, u.name as created_by_name,
             lf.title as learning_field_title
      FROM exercises e
      JOIN users u ON e.created_by = u.id
      JOIN learning_fields lf ON e.learning_field_id = lf.id
      WHERE e.status = 'pending'
      ORDER BY e.created_at DESC
    `);
    
    const processedExercises = exercises.map(exercise => ({
      ...exercise,
      content: exercise.content ? JSON.parse(exercise.content) : {}
    }));
    
    res.json({ success: true, data: processedExercises });
  } catch (error) {
    console.error('Get pending exercises error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch pending exercises' });
  }
});

app.put('/api/exercises/:id/approve', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.execute(
      'UPDATE exercises SET status = "approved" WHERE id = ?',
      [req.params.id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, error: 'Exercise not found' });
    }
    
    res.json({ success: true, data: { status: 'approved' } });
  } catch (error) {
    console.error('Approve exercise error:', error);
    res.status(500).json({ success: false, error: 'Failed to approve exercise' });
  }
});

app.put('/api/exercises/:id/reject', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.execute(
      'UPDATE exercises SET status = "rejected" WHERE id = ?',
      [req.params.id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, error: 'Exercise not found' });
    }
    
    res.json({ success: true, data: { status: 'rejected' } });
  } catch (error) {
    console.error('Reject exercise error:', error);
    res.status(500).json({ success: false, error: 'Failed to reject exercise' });
  }
});

app.post('/api/exercises/:id/submit', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { answer } = req.body;
    
    console.log('=== EXERCISE SUBMIT DEBUG ===');
    console.log('Exercise ID:', id);
    console.log('User answer:', answer, 'Type:', typeof answer);
    
    // Get exercise from database
    const [exercises] = await pool.execute(
      'SELECT * FROM exercises WHERE id = ?',
      [id]
    );
    
    if (exercises.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Exercise not found' 
      });
    }
    
    const exercise = exercises[0];
    const content = exercise.content ? JSON.parse(exercise.content) : {};
    
    console.log('Exercise type:', exercise.type);
    console.log('Exercise content:', content);
    console.log('Correct answer:', content.correctAnswer, 'Type:', typeof content.correctAnswer);
    
    let isCorrect = false;
    let feedback = '';
    
    // Check answer based on exercise type
    switch (exercise.type) {
      case 'multiple_choice':
        console.log('Comparing:', `"${answer}" === "${content.correctAnswer}"`);
        isCorrect = String(answer).trim() === String(content.correctAnswer).trim();
        feedback = isCorrect 
          ? 'Richtige Antwort!' 
          : `Falsch. Die richtige Antwort ist: ${content.correctAnswer}`;
        break;
        
      case 'fill_blank':
        const correctAnswers = content.correctAnswers || [];
        isCorrect = correctAnswers.some(correctAnswer => 
          String(answer).toLowerCase().trim() === String(correctAnswer).toLowerCase().trim()
        );
        feedback = isCorrect 
          ? 'Richtige Antwort!' 
          : `Falsch. Mögliche Antworten: ${correctAnswers.join(', ')}`;
        break;
        
      case 'terminal_input':
        const expectedCommand = content.expectedCommand || '';
        isCorrect = String(answer).trim() === String(expectedCommand).trim();
        feedback = isCorrect 
          ? 'Richtiger Befehl!' 
          : `Falsch. Erwarteter Befehl: ${expectedCommand}`;
        break;
        
      default:
        feedback = 'Unbekannter Übungstyp';
    }
    
    console.log('Result - Correct:', isCorrect);
    console.log('Feedback:', feedback);
    
    // Calculate points earned
    const pointsEarned = isCorrect ? (exercise.points || 1) : 0;
    
    res.json({
      success: true,
      data: {
        correct: isCorrect,
        feedback: feedback,
        pointsEarned: pointsEarned,
        totalPoints: exercise.points || 1,
        correctAnswer: content.correctAnswer // Zeige richtige Antwort für Debug
      }
    });
  } catch (error) {
    console.error('Submit exercise error:', error);
    res.status(500).json({ success: false, error: 'Failed to submit exercise' });
  }
});

app.delete('/api/exercises/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.execute('DELETE FROM exercises WHERE id = ?', [req.params.id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, error: 'Exercise not found' });
    }
    
    res.json({ success: true, data: [{ deleted: true }] });
  } catch (error) {
    console.error('Delete exercise error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete exercise' });
  }
});

// ========== KANBAN ENDPOINTS - ERWEITERT ==========
app.get('/api/kanban/columns', authenticateToken, async (req, res) => {
  try {
    console.log('=== KANBAN COLUMNS DEBUG ===');
    console.log('Fetching kanban columns for user:', req.user.username);
    
    // Get columns with detailed logging
    const [columns] = await pool.execute(`
      SELECT * FROM kanban_columns ORDER BY order_position ASC
    `);
    
    console.log('Raw columns from DB:', columns);
    
    // Get cards for each column with detailed logging
    const [cards] = await pool.execute(`
      SELECT kc.*, u.username as created_by_username, u.name as created_by_name
      FROM kanban_cards kc
      JOIN users u ON kc.created_by = u.id
      ORDER BY kc.created_at ASC
    `);
    
    console.log('Raw cards from DB:', cards);
    
    // Group cards by column with detailed processing
    const columnsWithCards = columns.map(column => {
      const columnCards = cards.filter(card => card.column_id === column.column_id);
      
      console.log(`Processing column ${column.column_id}:`, {
        id: column.column_id,
        title: column.title,
        color: column.color,
        cardsCount: columnCards.length
      });
      
      const processedCards = columnCards.map(card => ({
        id: card.id,
        title: card.title,
        content: card.content,
        priority: card.priority,
        tags: JSON.parse(card.tags || '[]'),
        createdBy: card.created_by,
        createdByName: card.created_by_name || card.created_by_username,
        createdAt: card.created_at,
        updatedAt: card.updated_at,
        dueDate: card.due_date
      }));
      
      return {
        id: column.column_id,
        title: column.title,
        color: column.color,
        order: column.order_position,
        cards: processedCards
      };
    });
    
    console.log('Final processed columns:', columnsWithCards);
    
    res.json({ success: true, data: columnsWithCards });
  } catch (error) {
    console.error('Get kanban columns error:', error);
    console.error('Error details:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({ success: false, error: 'Failed to fetch kanban columns: ' + error.message });
  }
});

app.post('/api/kanban/cards', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('=== CREATE KANBAN CARD DEBUG ===');
    console.log('Request body:', req.body);
    console.log('User:', req.user);
    
    const { title, content, priority, tags, dueDate } = req.body;
    
    // Validation
    if (!title || !title.trim()) {
      return res.status(400).json({ success: false, error: 'Title is required' });
    }
    
    if (!content || !content.trim()) {
      return res.status(400).json({ success: false, error: 'Content is required' });
    }
    
    // Default to "todo" column
    const columnId = 'todo';
    const cleanTags = Array.isArray(tags) ? tags : [];
    
    console.log('Creating card with params:', {
      title: title.trim(),
      content: content.trim(),
      priority: priority || 'medium',
      tags: cleanTags,
      columnId,
      userId: req.user.id,
      dueDate: dueDate || null
    });
    
    const [result] = await pool.execute(
      'INSERT INTO kanban_cards (title, content, priority, tags, column_id, created_by, due_date, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())',
      [
        title.trim(),
        content.trim(),
        priority || 'medium',
        JSON.stringify(cleanTags),
        columnId,
        req.user.id,
        dueDate || null
      ]
    );
    
    console.log('Card created with ID:', result.insertId);
    
    // Get the created card with user info
    const [cards] = await pool.execute(`
      SELECT kc.*, u.username as created_by_username, u.name as created_by_name
      FROM kanban_cards kc
      JOIN users u ON kc.created_by = u.id
      WHERE kc.id = ?
    `, [result.insertId]);
    
    if (cards.length === 0) {
      throw new Error('Failed to fetch created card');
    }
    
    const card = cards[0];
    
    const responseCard = {
      id: card.id,
      title: card.title,
      content: card.content,
      priority: card.priority,
      tags: JSON.parse(card.tags || '[]'),
      createdBy: card.created_by,
      createdByName: card.created_by_name || card.created_by_username,
      createdAt: card.created_at,
      updatedAt: card.updated_at,
      dueDate: card.due_date
    };
    
    console.log('Returning card:', responseCard);
    
    res.json({
      success: true,
      data: responseCard
    });
  } catch (error) {
    console.error('Create kanban card error:', error);
    console.error('Error details:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({ success: false, error: 'Failed to create kanban card: ' + error.message });
  }
});

app.put('/api/kanban/cards/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('=== UPDATE KANBAN CARD DEBUG ===');
    console.log('Card ID:', req.params.id);
    console.log('Request body:', req.body);
    
    const { title, content, priority, tags, dueDate } = req.body;
    
    const cleanTags = Array.isArray(tags) ? tags : [];
    
    const [result] = await pool.execute(
      'UPDATE kanban_cards SET title = ?, content = ?, priority = ?, tags = ?, due_date = ?, updated_at = NOW() WHERE id = ?',
      [
        title,
        content,
        priority,
        JSON.stringify(cleanTags),
        dueDate || null,
        req.params.id
      ]
    );
    
    console.log('Update result:', result);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, error: 'Card not found' });
    }
    
    // Get updated card
    const [cards] = await pool.execute(`
      SELECT kc.*, u.username as created_by_username, u.name as created_by_name
      FROM kanban_cards kc
      JOIN users u ON kc.created_by = u.id
      WHERE kc.id = ?
    `, [req.params.id]);
    
    if (cards.length === 0) {
      return res.status(404).json({ success: false, error: 'Card not found after update' });
    }
    
    const card = cards[0];
    
    const responseCard = {
      id: card.id,
      title: card.title,
      content: card.content,
      priority: card.priority,
      tags: JSON.parse(card.tags || '[]'),
      createdBy: card.created_by,
      createdByName: card.created_by_name || card.created_by_username,
      createdAt: card.created_at,
      updatedAt: card.updated_at,
      dueDate: card.due_date
    };
    
    console.log('Returning updated card:', responseCard);
    
    res.json({
      success: true,
      data: responseCard
    });
  } catch (error) {
    console.error('Update kanban card error:', error);
    res.status(500).json({ success: false, error: 'Failed to update kanban card: ' + error.message });
  }
});

app.delete('/api/kanban/cards/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('=== DELETE KANBAN CARD DEBUG ===');
    console.log('Deleting card ID:', req.params.id);
    console.log('User:', req.user.username);
    
    const [result] = await pool.execute('DELETE FROM kanban_cards WHERE id = ?', [req.params.id]);
    
    console.log('Delete result:', result);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, error: 'Card not found' });
    }
    
    res.json({ success: true, data: { deleted: true } });
  } catch (error) {
    console.error('Delete kanban card error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete kanban card: ' + error.message });
  }
});

// ERWEITERTE MOVE FUNKTION MIT DEBUGGING
app.put('/api/kanban/cards/move', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('=== MOVE KANBAN CARD DEBUG ===');
    console.log('Request body:', req.body);
    console.log('User:', req.user.username, req.user.role);
    
    const { cardId, toColumn } = req.body;
    
    if (!cardId || !toColumn) {
      return res.status(400).json({ 
        success: false, 
        error: 'cardId and toColumn are required' 
      });
    }
    
    console.log('Moving card:', cardId, 'to column:', toColumn);
    
    // Check if card exists first
    const [existingCards] = await pool.execute('SELECT * FROM kanban_cards WHERE id = ?', [cardId]);
    
    if (existingCards.length === 0) {
      return res.status(404).json({ success: false, error: 'Card not found' });
    }
    
    console.log('Card found:', existingCards[0]);
    
    // Check if target column exists
    const [existingColumns] = await pool.execute('SELECT * FROM kanban_columns WHERE column_id = ?', [toColumn]);
    
    if (existingColumns.length === 0) {
      return res.status(404).json({ success: false, error: 'Target column not found' });
    }
    
    console.log('Target column found:', existingColumns[0]);
    
    // Perform the move
    const [result] = await pool.execute(
      'UPDATE kanban_cards SET column_id = ?, updated_at = NOW() WHERE id = ?',
      [toColumn, cardId]
    );
    
    console.log('Move result:', result);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, error: 'Failed to move card' });
    }
    
    // Verify the move
    const [verifyCards] = await pool.execute('SELECT * FROM kanban_cards WHERE id = ?', [cardId]);
    console.log('Card after move:', verifyCards[0]);
    
    res.json({ 
      success: true, 
      data: { 
        moved: true,
        cardId: cardId,
        fromColumn: existingCards[0].column_id,
        toColumn: toColumn,
        updatedAt: new Date().toISOString()
      } 
    });
  } catch (error) {
    console.error('Move kanban card error:', error);
    console.error('Error details:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({ success: false, error: 'Failed to move kanban card: ' + error.message });
  }
});

// USERS ENDPOINTS
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [users] = await pool.execute(
      'SELECT id, username, name, role, posts_count, last_login, created_at FROM users ORDER BY created_at DESC'
    );
    
    res.json({ success: true, data: users });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch users' });
  }
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    if (req.params.id == req.user.id) {
      return res.status(400).json({ success: false, error: 'Cannot delete your own account' });
    }
    
    await pool.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.json({ success: true, data: { deleted: true } });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete user' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ success: true, data: { status: 'OK', timestamp: new Date().toISOString() } });
});

// API Root endpoint
app.get('/api/', (req, res) => {
  res.json({ 
    success: true, 
    message: 'klasse41-hub API', 
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth/*',
      learningFields: '/api/learning-fields',
      posts: '/api/posts',
      users: '/api/users',
      exercises: '/api/exercises',
      kanban: '/api/kanban/*',
      health: '/api/health'
    }
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
  console.log(`Database: ${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`);
});