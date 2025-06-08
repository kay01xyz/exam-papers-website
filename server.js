const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fileUpload = require('express-fileupload');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// 中間件設置
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(fileUpload({
    createParentPath: true,
    limits: { 
        fileSize: 10 * 1024 * 1024 // 10MB 限制
    }
}));

// 建立必要資料夾
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('✅ 建立上傳資料夾:', uploadsDir);
}

// 建立資料庫連接
const db = new sqlite3.Database('exam_papers.db');

// 初始化資料庫表格
db.serialize(() => {
    // 用戶表
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_admin INTEGER DEFAULT 0
    )`);

    // 試卷表
    db.run(`CREATE TABLE IF NOT EXISTS papers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        grade TEXT NOT NULL,
        subject TEXT NOT NULL,
        school TEXT,
        exam_type TEXT,
        year INTEGER,
        filename TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_size INTEGER,
        uploader_id INTEGER,
        downloads INTEGER DEFAULT 0,
        upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'pending',
        FOREIGN KEY (uploader_id) REFERENCES users (id)
    )`);

    // 建立管理員帳號（如果不存在）
    db.get("SELECT COUNT(*) as count FROM users WHERE is_admin = 1", (err, row) => {
        if (row.count === 0) {
            bcrypt.hash('admin123', 10, (err, hash) => {
                if (!err) {
                    db.run(`INSERT INTO users (username, email, password, is_admin) 
                            VALUES (?, ?, ?, ?)`, 
                           ['admin', 'admin@example.com', hash, 1], 
                           function(err) {
                               if (!err) {
                                   console.log('✅ 管理員帳號已建立: admin / admin123');
                               }
                           });
                }
            });
        }
    });

    // 插入示例數據
    db.get("SELECT COUNT(*) as count FROM papers", (err, row) => {
        if (row.count === 0) {
            const samplePapers = [
                ['小五數學期考試卷', 'P5', '數學', '聖保羅書院小學', '考試', 2024, 'sample1.pdf', '/uploads/sample1.pdf', 1024000, null, 245, 'approved'],
                ['中一英文測驗卷', 'F1', '英文', '屯門天主教中學', '測驗', 2024, 'sample2.pdf', '/uploads/sample2.pdf', 856000, null, 189, 'approved'],
                ['小六常識綜合練習', 'P6', '常識', '將軍澳官立小學', '練習', 2024, 'sample3.pdf', '/uploads/sample3.pdf', 2048000, null, 156, 'approved'],
                ['中二數學月考', 'F2', '數學', '聖芳濟各書院', '考試', 2024, 'sample4.pdf', '/uploads/sample4.pdf', 1456000, null, 234, 'approved'],
                ['小四英文工作紙', 'P4', '英文', '黃埔宣道小學', '練習', 2024, 'sample5.pdf', '/uploads/sample5.pdf', 789000, null, 178, 'approved']
            ];

            const stmt = db.prepare(`INSERT INTO papers 
                (title, grade, subject, school, exam_type, year, filename, file_path, file_size, uploader_id, downloads, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
            
            samplePapers.forEach(paper => stmt.run(paper));
            stmt.finalize();
            console.log('✅ 示例試卷數據已加載');
        }
    });
});

// 中間件：驗證JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: '需要登入' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: '無效的登入狀態' });
        }
        req.user = user;
        next();
    });
}

// API 路由：用戶註冊
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ 
            success: false, 
            message: '請填寫所有必要欄位' 
        });
    }

    if (password.length < 6) {
        return res.status(400).json({ 
            success: false, 
            message: '密碼至少需要6個字符' 
        });
    }

    try {
        // 檢查用戶是否已存在
        db.get("SELECT id FROM users WHERE username = ? OR email = ?", [username, email], async (err, row) => {
            if (err) {
                return res.status(500).json({ success: false, message: '註冊失敗' });
            }

            if (row) {
                return res.status(400).json({ 
                    success: false, 
                    message: '用戶名或信箱已存在' 
                });
            }

            // 加密密碼
            const hashedPassword = await bcrypt.hash(password, 10);

            // 建立用戶
            db.run("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                   [username, email, hashedPassword], 
                   function(err) {
                       if (err) {
                           return res.status(500).json({ 
                               success: false, 
                               message: '註冊失敗' 
                           });
                       }

                       res.json({ 
                           success: true, 
                           message: '註冊成功！',
                           userId: this.lastID
                       });
                   });
        });
    } catch (error) {
        console.error('註冊錯誤:', error);
        res.status(500).json({ success: false, message: '註冊失敗' });
    }
});

// API 路由：用戶登入
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ 
            success: false, 
            message: '請填寫用戶名和密碼' 
        });
    }

    db.get("SELECT * FROM users WHERE username = ? OR email = ?", [username, username], async (err, user) => {
        if (err) {
            return res.status(500).json({ success: false, message: '登入失敗' });
        }

        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: '用戶名或密碼錯誤' 
            });
        }

        try {
            const validPassword = await bcrypt.compare(password, user.password);
            
            if (!validPassword) {
                return res.status(401).json({ 
                    success: false, 
                    message: '用戶名或密碼錯誤' 
                });
            }

            // 生成JWT
            const token = jwt.sign(
                { 
                    userId: user.id, 
                    username: user.username,
                    isAdmin: user.is_admin 
                }, 
                JWT_SECRET, 
                { expiresIn: '24h' }
            );

            res.json({ 
                success: true, 
                message: '登入成功！',
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    isAdmin: user.is_admin
                }
            });
        } catch (error) {
            console.error('登入錯誤:', error);
            res.status(500).json({ success: false, message: '登入失敗' });
        }
    });
});

// API 路由：獲取用戶資料
app.get('/api/profile', authenticateToken, (req, res) => {
    db.get("SELECT id, username, email, created_at, is_admin FROM users WHERE id = ?", 
           [req.user.userId], (err, user) => {
        if (err) {
            return res.status(500).json({ success: false, message: '獲取用戶資料失敗' });
        }

        if (!user) {
            return res.status(404).json({ success: false, message: '用戶不存在' });
        }

        res.json({ success: true, user });
    });
});

// API 路由：獲取試卷列表
app.get('/api/papers', (req, res) => {
    const { grade, subject, school, keyword, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    let sql = `SELECT p.*, u.username as uploader_name 
               FROM papers p 
               LEFT JOIN users u ON p.uploader_id = u.id 
               WHERE p.status = 'approved'`;
    const params = [];

    if (grade) {
        sql += ' AND p.grade = ?';
        params.push(grade);
    }
    if (subject) {
        sql += ' AND p.subject = ?';
        params.push(subject);
    }
    if (school) {
        sql += ' AND p.school LIKE ?';
        params.push(`%${school}%`);
    }
    if (keyword) {
        sql += ' AND (p.title LIKE ? OR p.school LIKE ?)';
        params.push(`%${keyword}%`, `%${keyword}%`);
    }

    sql += ' ORDER BY p.upload_date DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    db.all(sql, params, (err, rows) => {
        if (err) {
            console.error('獲取試卷錯誤:', err);
            return res.status(500).json({ 
                success: false, 
                message: '獲取試卷失敗' 
            });
        }

        // 獲取總數
        let countSql = 'SELECT COUNT(*) as total FROM papers WHERE status = "approved"';
        const countParams = [];

        if (grade || subject || school || keyword) {
            countSql = `SELECT COUNT(*) as total FROM papers WHERE status = 'approved'`;
            if (grade) {
                countSql += ' AND grade = ?';
                countParams.push(grade);
            }
            if (subject) {
                countSql += ' AND subject = ?';
                countParams.push(subject);
            }
            if (school) {
                countSql += ' AND school LIKE ?';
                countParams.push(`%${school}%`);
            }
            if (keyword) {
                countSql += ' AND (title LIKE ? OR school LIKE ?)';
                countParams.push(`%${keyword}%`, `%${keyword}%`);
            }
        }

        db.get(countSql, countParams, (err, countRow) => {
            res.json({ 
                success: true, 
                data: rows,
                pagination: {
                    total: countRow.total,
                    page: parseInt(page),
                    pages: Math.ceil(countRow.total / limit)
                }
            });
        });
    });
});

// API 路由：上傳試卷
app.post('/api/upload', authenticateToken, (req, res) => {
    if (!req.files || !req.files.file) {
        return res.status(400).json({ 
            success: false, 
            message: '請選擇要上傳的檔案' 
        });
    }

    const { title, grade, subject, school, examType, year } = req.body;
    const file = req.files.file;

    // 驗證檔案類型
    if (!file.name.toLowerCase().endsWith('.pdf')) {
        return res.status(400).json({ 
            success: false, 
            message: '只支援 PDF 檔案' 
        });
    }

    // 生成唯一檔名
    const fileName = Date.now() + '-' + file.name.replace(/[^a-zA-Z0-9.-]/g, '_');
    const filePath = path.join(uploadsDir, fileName);

    // 移動檔案
    file.mv(filePath, (err) => {
        if (err) {
            console.error('檔案上傳錯誤:', err);
            return res.status(500).json({ 
                success: false, 
                message: '檔案上傳失敗' 
            });
        }

        // 儲存到資料庫
        db.run(`INSERT INTO papers 
                (title, grade, subject, school, exam_type, year, filename, file_path, file_size, uploader_id) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
               [title, grade, subject, school, examType, year, fileName, `/uploads/${fileName}`, file.size, req.user.userId],
               function(err) {
                   if (err) {
                       console.error('儲存試卷錯誤:', err);
                       // 刪除已上傳的檔案
                       fs.unlink(filePath, () => {});
                       return res.status(500).json({ 
                           success: false, 
                           message: '儲存試卷資料失敗' 
                       });
                   }

                   res.json({ 
                       success: true, 
                       message: '試卷上傳成功，等待審核',
                       paperId: this.lastID
                   });
               });
    });
});

// API 路由：模擬下載
app.get('/api/download/:paperId', (req, res) => {
    const paperId = req.params.paperId;
    
    // 更新下載次數
    db.run("UPDATE papers SET downloads = downloads + 1 WHERE id = ?", [paperId], function(err) {
        if (err) {
            console.error('更新下載次數失敗:', err);
            return res.status(500).json({ success: false, message: '下載失敗' });
        }
        
        res.json({ 
            success: true, 
            message: '下載成功！',
            downloadUrl: `https://example.com/download/${paperId}.pdf`
        });
    });
});

// API 路由：獲取統計資料
app.get('/api/stats', (req, res) => {
    const queries = [
        "SELECT COUNT(*) as total_papers FROM papers WHERE status = 'approved'",
        "SELECT COUNT(DISTINCT school) as total_schools FROM papers WHERE school IS NOT NULL AND status = 'approved'",
        "SELECT SUM(downloads) as total_downloads FROM papers WHERE status = 'approved'",
        "SELECT COUNT(*) as total_users FROM users"
    ];

    Promise.all(queries.map(query => {
        return new Promise((resolve, reject) => {
            db.get(query, (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }))
    .then(results => {
        res.json({
            success: true,
            data: {
                totalPapers: results[0].total_papers || 0,
                totalSchools: results[1].total_schools || 0,
                totalDownloads: results[2].total_downloads || 0,
                totalUsers: results[3].total_users || 0
            }
        });
    })
    .catch(error => {
        console.error('統計錯誤:', error);
        res.status(500).json({ 
            success: false, 
            message: '獲取統計失敗' 
        });
    });
});

// 首頁路由
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 啟動服務器
app.listen(PORT, () => {
    console.log(`🚀 試卷網站後端運行於 http://localhost:${PORT}`);
    console.log('📂 上傳資料夾:', uploadsDir);
    console.log('🗄️ 資料庫檔案: exam_papers.db');
    console.log('👤 預設管理員: admin / admin123');
});