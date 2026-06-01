const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || 'truthpulse_secret_key_2026';

const express = require('express');
const multer = require('multer');
const cors = require('cors');
const mongoose = require('mongoose');
const axios = require('axios');
const cheerio = require('cheerio');
const nodemailer = require('nodemailer');

const {
  GoogleGenerativeAI,
} = require('@google/generative-ai');

const {
  GoogleAIFileManager,
} = require('@google/generative-ai/server');

const app = express();

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ================================
// MONGODB CONNECTION
// ================================

mongoose.connect(process.env.MONGO_URI)

.then(() => {

  console.log("MongoDB Connected");

})

.catch((err) => {

  console.log(err);

});

// ================================
// MONGODB SCHEMA
// ================================

const scanSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  aiProbability: String,
  trustScore: String,
  status: String,
  explanation: String,
  filename: String,
  mediaType: String,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Scan = mongoose.model(
  "Scan",
  scanSchema
);

// ================================
// USER SCHEMA & MODEL
// ================================

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
  profilePhoto: {
    type: String,
    default: '',
  },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model('User', userSchema);

// ================================
// EMAIL TRANSPORTER SETUP
// ================================

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ================================
// AUTH MIDDLEWARE
// ================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// ================================
// AUTH: REGISTER
// ================================

app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign(
      { id: user._id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Send Admin Notification
    const adminMailOptions = {
      from: '"TruthPulse App" <no-reply@truthpulse.com>',
      to: process.env.EMAIL_USER,
      subject: '🚀 New User Registration - TruthPulse!',
      text: `A new user has just registered on TruthPulse!\n\nName: ${user.name}\nEmail: ${user.email}\nDate: ${new Date().toLocaleString()}`,
    };
    transporter.sendMail(adminMailOptions).catch(err => console.error("Admin notification failed:", err));

    res.status(201).json({
      message: 'Account created successfully',
      token,
      user: { id: user._id, name: user.name, email: user.email, profilePhoto: user.profilePhoto },
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// ================================
// AUTH: LOGIN
// ================================

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Send Admin Notification
    const adminMailOptions = {
      from: '"TruthPulse App" <no-reply@truthpulse.com>',
      to: process.env.EMAIL_USER,
      subject: '👋 User Logged In - TruthPulse',
      text: `A user has just logged into TruthPulse!\n\nName: ${user.name}\nEmail: ${user.email}\nDate: ${new Date().toLocaleString()}`,
    };
    transporter.sendMail(adminMailOptions).catch(err => console.error("Admin notification failed:", err));

    res.json({
      message: 'Login successful',
      token,
      user: { id: user._id, name: user.name, email: user.email, profilePhoto: user.profilePhoto },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// ================================
// AUTH: GET CURRENT USER
// ================================

app.get('/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// ================================
// AUTH: UPDATE PROFILE
// ================================

app.put('/auth/update', authenticateToken, async (req, res) => {
  try {
    const { name, password, profilePhoto } = req.body;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    if (name) user.name = name.trim();
    if (profilePhoto) user.profilePhoto = profilePhoto;
    if (password && password.length >= 6) {
      const salt = await bcrypt.genSalt(12);
      user.password = await bcrypt.hash(password, salt);
    }
    
    await user.save();
    res.json({ message: 'Profile updated successfully', user: { id: user._id, name: user.name, email: user.email, profilePhoto: user.profilePhoto } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ================================
// AUTH: FORGOT PASSWORD
// ================================

app.post('/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({ error: 'No account with that email found' });
    }

    // Generate 6-digit code
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetPasswordToken = resetCode;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const mailOptions = {
      from: '"TruthPulse App" <no-reply@truthpulse.com>',
      to: user.email,
      subject: 'Password Reset Code - TruthPulse',
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\nYour password reset verification code is: ${resetCode}\n\nThis code will expire in 1 hour.\n\nIf you did not request this, please ignore this email and your password will remain unchanged.\n`,
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error('Email send error:', err);
        return res.status(500).json({ error: 'Error sending email' });
      }
      res.json({ message: 'Reset code sent to email' });
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process forgot password request' });
  }
});

// ================================
// AUTH: RESET PASSWORD
// ================================

app.post('/auth/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    
    if (!email || !token || !newPassword) {
      return res.status(400).json({ error: 'Email, code, and new password are required' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const user = await User.findOne({
      email: email.toLowerCase(),
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification code' });
    }

    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(newPassword, salt);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password has been reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ================================
// FILE UPLOAD CONFIGURATION
// ================================

const upload = multer({
  dest: 'uploads/',
});

// ================================
// GEMINI AI CONFIGURATION
// ================================

const genAI = new GoogleGenerativeAI(
  process.env.GEMINI_API_KEY
);

// ================================
// ANALYZE MEDIA API
// ================================

app.post(
  '/analyze',
  authenticateToken,
  upload.single('media'),

  async (req, res) => {

    try {
      const deepScan = req.body.deepScan === 'true';
      // LOAD GEMINI MODEL

      const model =
        genAI.getGenerativeModel({

          model: "gemini-2.5-flash-lite",

        });

      // PROCESS MEDIA
      let fileMimeType = req.file.mimetype;
      if (fileMimeType === 'application/octet-stream' || !fileMimeType) {
        const ext = (req.file.originalname || '').split('.').pop().toLowerCase();
        if (['jpg', 'jpeg'].includes(ext)) fileMimeType = 'image/jpeg';
        else if (ext === 'png') fileMimeType = 'image/png';
        else if (ext === 'webp') fileMimeType = 'image/webp';
        else if (ext === 'mp4') fileMimeType = 'video/mp4';
        else if (['mp3', 'wav', 'm4a', 'aac'].includes(ext)) fileMimeType = 'audio/mp3';
        else fileMimeType = 'image/jpeg';
      }
      let mediaPart;
      const scanLevel = deepScan ? "Perform a rigorous, multi-step deep scan analysis" : "Perform a standard analysis";
      let dynamicPrompt = `Analyze this uploaded media carefully. ${scanLevel}`;

      if (fileMimeType.startsWith('video/') || fileMimeType.startsWith('audio/')) {
        const fileManager = new GoogleAIFileManager(process.env.GEMINI_API_KEY);
        
        const uploadResponse = await fileManager.uploadFile(req.file.path, {
          mimeType: fileMimeType,
          displayName: req.file.originalname || "upload",
        });
        
        let fileState = await fileManager.getFile(uploadResponse.file.name);
        while (fileState.state === 'PROCESSING') {
          await new Promise((resolve) => setTimeout(resolve, 3000));
          fileState = await fileManager.getFile(uploadResponse.file.name);
        }
        
        if (fileState.state === 'FAILED') {
          throw new Error('Media processing failed.');
        }

        mediaPart = {
          fileData: {
            mimeType: uploadResponse.file.mimeType,
            fileUri: uploadResponse.file.uri
          }
        };

        if (fileMimeType.startsWith('audio/')) {
          dynamicPrompt = "Analyze this uploaded audio/voice recording carefully. Determine if it is a deepfake, an AI voice clone, or an authentic human voice. Look for robotic intonations, unnatural breathing patterns, or synthesis artifacts.";
        } else {
          dynamicPrompt = "Analyze this uploaded video carefully. Determine whether the video appears authentic or AI-generated. Look for temporal inconsistencies, morphing artifacts, unnatural physics, or deepfake face swapping.";
        }
      } else {
        const imageBuffer = fs.readFileSync(req.file.path);
        mediaPart = {
          inlineData: {
            data: imageBuffer.toString("base64"),
            mimeType: fileMimeType,
          },
        };
        dynamicPrompt = "Analyze this uploaded image carefully. Determine whether the media appears authentic or AI-generated. Look for visual inconsistencies, AI-generated artifacts, and editing indicators.";
      }

      // AI PROMPT
      const prompt = `
${dynamicPrompt}

You MUST return your response as a valid JSON object without any markdown formatting or backticks. 
The JSON must have the following exact structure:
{
  "aiProbability": number (from 0 to 100, representing the probability the media is AI generated),
  "trustScore": number (from 0 to 100, representing how trustworthy/authentic the media is),
  "status": string (either "Authentic" or "AI Generated"),
  "explanation": string (short professional explanation of the analysis)
}
`;

      // SEND TO GEMINI

      const result =
        await model.generateContent([

          prompt,
          mediaPart,

        ]);

      // GET RESPONSE

      let rawText = result.response.text();
      rawText = rawText.replace(/```json/gi, "").replace(/```/g, "").trim();
      
      let aiResponse;
      try {
        aiResponse = JSON.parse(rawText);
      } catch (err) {
        console.error("JSON Parse Error:", rawText);
        aiResponse = {
          aiProbability: 50,
          trustScore: 50,
          status: "Inconclusive",
          explanation: rawText
        };
      }

      // AI SCORES

      const trustScore = Number(aiResponse.trustScore) || 50;
      const aiProbability = 100 - trustScore;
      const status = aiResponse.status;
      const explanationText = aiResponse.explanation;

      // ================================
      // SAVE TO MONGODB
      // ================================

      const newScan = new Scan({
        userId: req.user.id,
        aiProbability:
          aiProbability.toString() + "%",

        trustScore:
          trustScore.toString() + "%",

        status: status,

        explanation: explanationText,
        filename: req.file ? (req.file.originalname || 'upload') : 'upload',
        mediaType: fileMimeType,

      });

      await newScan.save();

      // ================================
      // SEND RESULT
      // ================================

      res.json({

        aiProbability:
          aiProbability.toString() + "%",

        trustScore:
          trustScore.toString() + "%",

        status: status,

        explanation: explanationText,

      });

      // CLEANUP
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }

    } catch (error) {

      console.log(error);

      // CLEANUP
      if (req.file && req.file.path && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }

      res.status(500).json({

        error:
          "AI Analysis failed",

      });
    }
  }
);

// ================================
// ANALYZE TEXT API
// ================================

app.post(
  '/analyze-text',
  authenticateToken,
  async (req, res) => {
    try {
      const { text } = req.body;
      if (!text) {
        return res.status(400).json({ error: "Text is required" });
      }

      const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });

      const prompt = `
Analyze the following text carefully.
Determine whether this text appears to be written by a human or generated by an AI (like ChatGPT, Claude, etc).
Provide a professional analysis of:
- perplexity and burstiness
- AI-specific vocabulary and stylistic fingerprints
- logical flow and sentence structure

You MUST return your response as a valid JSON object without any markdown formatting or backticks. 
The JSON must have the following exact structure:
{
  "aiProbability": number (from 0 to 100, representing the probability the text is AI generated),
  "trustScore": number (from 0 to 100, representing how trustworthy/human-written the text is),
  "status": string (either "Authentic" or "AI Generated"),
  "explanation": string (short professional explanation of the analysis)
}

Text to analyze:
"${text}"
`;

      const result = await model.generateContent([prompt]);
      
      let rawText = result.response.text();
      rawText = rawText.replace(/```json/gi, "").replace(/```/g, "").trim();
      
      let aiResponse;
      try {
        aiResponse = JSON.parse(rawText);
      } catch (err) {
        console.error("JSON Parse Error:", rawText);
        aiResponse = {
          aiProbability: 50,
          trustScore: 50,
          status: "Inconclusive",
          explanation: rawText
        };
      }

      const trustScore = Number(aiResponse.trustScore) || 50;
      const aiProbability = 100 - trustScore;
      const status = aiResponse.status;
      const explanationText = aiResponse.explanation;

      const newScan = new Scan({
        userId: req.user.id,
        aiProbability: aiProbability.toString() + "%",
        trustScore: trustScore.toString() + "%",
        status: status,
        explanation: explanationText,
        filename: "Text Snippet",
        mediaType: "text/plain",
      });

      await newScan.save();

      res.json({
        aiProbability: aiProbability.toString() + "%",
        trustScore: trustScore.toString() + "%",
        status: status,
        explanation: explanationText,
      });

    } catch (error) {
      console.log(error);
      res.status(500).json({ error: "Text Analysis failed" });
    }
  }
);

// ================================
// ANALYZE URL API
// ================================

app.post(
  '/analyze-url',
  authenticateToken,
  async (req, res) => {
    try {
      const { url } = req.body;
      if (!url) {
        return res.status(400).json({ error: "URL is required" });
      }

      const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });

      const prompt = `
Analyze the content at the following URL. Note: you may need to rely on the URL structure or general web context if direct crawling fails.
Determine whether the content typically found at this URL or similar URLs appears to be AI-generated or human-created.
Analyze the likelihood of it being a deepfake, synthetic media, or AI-generated text based on the URL context.

You MUST return your response as a valid JSON object without any markdown formatting or backticks. 
The JSON must have the following exact structure:
{
  "aiProbability": number (from 0 to 100),
  "trustScore": number (from 0 to 100),
  "status": string (either "Authentic" or "AI Generated"),
  "explanation": string (short professional explanation of the analysis)
}

URL to analyze:
"${url}"
`;

      const result = await model.generateContent([prompt]);
      
      let rawText = result.response.text();
      rawText = rawText.replace(/```json/gi, "").replace(/```/g, "").trim();
      
      let aiResponse;
      try {
        aiResponse = JSON.parse(rawText);
      } catch (err) {
        console.error("JSON Parse Error:", rawText);
        aiResponse = {
          aiProbability: 50,
          trustScore: 50,
          status: "Inconclusive",
          explanation: rawText
        };
      }

      const trustScoreNum = Number(aiResponse.trustScore) || 50;
      const aiProbNum = 100 - trustScoreNum;

      const newScan = new Scan({
        userId: req.user.id,
        aiProbability: aiProbNum.toString() + "%",
        trustScore: trustScoreNum.toString() + "%",
        status: aiResponse.status,
        explanation: aiResponse.explanation,
        filename: url,
        mediaType: "url",
      });

      await newScan.save();

      res.json({
        aiProbability: aiProbNum.toString() + "%",
        trustScore: trustScoreNum.toString() + "%",
        status: aiResponse.status,
        explanation: aiResponse.explanation,
      });

    } catch (error) {
      console.log(error);
      res.status(500).json({ error: "URL Analysis failed" });
    }
  }
);

// ================================
// ANALYZE BATCH API
// ================================

app.post(
  '/analyze-batch',
  authenticateToken,
  upload.array('media', 10),
  async (req, res) => {
    try {
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: "No files uploaded" });
      }

      const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });
      const results = [];

      for (let file of req.files) {
        let fileMimeType = file.mimetype;
        if (fileMimeType === 'application/octet-stream' || !fileMimeType) {
          const ext = (file.originalname || '').split('.').pop().toLowerCase();
          if (['jpg', 'jpeg'].includes(ext)) fileMimeType = 'image/jpeg';
          else if (ext === 'png') fileMimeType = 'image/png';
          else if (ext === 'webp') fileMimeType = 'image/webp';
          else if (ext === 'mp4') fileMimeType = 'video/mp4';
          else if (['mp3', 'wav', 'm4a', 'aac'].includes(ext)) fileMimeType = 'audio/mp3';
          else fileMimeType = 'image/jpeg';
        }
        let mediaPart;
        let dynamicPrompt = "Analyze this uploaded media carefully.";

        if (fileMimeType.startsWith('video/') || fileMimeType.startsWith('audio/')) {
          const fileManager = new GoogleAIFileManager(process.env.GEMINI_API_KEY);
          const uploadResponse = await fileManager.uploadFile(file.path, {
            mimeType: fileMimeType,
            displayName: file.originalname || "upload",
          });
          
          let fileState = await fileManager.getFile(uploadResponse.file.name);
          while (fileState.state === 'PROCESSING') {
            await new Promise((resolve) => setTimeout(resolve, 3000));
            fileState = await fileManager.getFile(uploadResponse.file.name);
          }
          
          if (fileState.state === 'FAILED') continue;

          mediaPart = { fileData: { mimeType: uploadResponse.file.mimeType, fileUri: uploadResponse.file.uri } };
          if (fileMimeType.startsWith('audio/')) {
            dynamicPrompt = "Analyze this uploaded audio/voice recording carefully. Determine if it is a deepfake or authentic.";
          } else {
            dynamicPrompt = "Analyze this uploaded video carefully. Determine whether the video appears authentic or AI-generated.";
          }
        } else {
          const imageBuffer = fs.readFileSync(file.path);
          mediaPart = { inlineData: { data: imageBuffer.toString("base64"), mimeType: fileMimeType } };
          dynamicPrompt = "Analyze this uploaded image carefully. Determine whether the media appears authentic or AI-generated.";
        }

        const prompt = `
${dynamicPrompt}
You MUST return your response as a valid JSON object without any markdown formatting or backticks. 
{
  "aiProbability": number (from 0 to 100),
  "trustScore": number (from 0 to 100),
  "status": string (either "Authentic" or "AI Generated"),
  "explanation": string (short professional explanation)
}
`;
        try {
          const result = await model.generateContent([prompt, mediaPart]);
          let rawText = result.response.text();
          rawText = rawText.replace(/```json/gi, "").replace(/```/g, "").trim();
          let aiResponse = JSON.parse(rawText);
          
          const trustScoreNum = Number(aiResponse.trustScore) || 50;
          const aiProbNum = 100 - trustScoreNum;
          
          const newScan = new Scan({
            userId: req.user.id,
            aiProbability: aiProbNum.toString() + "%",
            trustScore: trustScoreNum.toString() + "%",
            status: aiResponse.status,
            explanation: aiResponse.explanation,
            filename: file.originalname || 'upload',
            mediaType: fileMimeType,
          });
          await newScan.save();
          
          results.push({
            filename: file.originalname,
            aiProbability: aiProbNum.toString() + "%",
            trustScore: trustScoreNum.toString() + "%",
            status: aiResponse.status,
            explanation: aiResponse.explanation,
          });
        } catch (err) {
          console.error("Batch parse error:", err);
        }

        if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
      }

      res.json({ results });
    } catch (error) {
      console.log(error);
      if (req.files) {
        req.files.forEach(f => {
          if (fs.existsSync(f.path)) fs.unlinkSync(f.path);
        });
      }
      res.status(500).json({ error: "Batch Analysis failed" });
    }
  }
);

// ================================
// GET SCAN HISTORY API
// ================================

app.get('/history', authenticateToken, async (req, res) => {
  try {
    const scans = await Scan.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(scans);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

// ================================
// DELETE SCAN HISTORY API
// ================================

app.delete('/history', authenticateToken, async (req, res) => {
  try {
    await Scan.deleteMany({ userId: req.user.id });
    res.json({ message: "History cleared successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to clear history" });
  }
});

// ================================
// ANALYZE SOCIAL PROFILE
// ================================
app.post('/analyze-social', authenticateToken, async (req, res) => {
  try {
    const { handle, deepScan } = req.body;
    if (!handle) return res.status(400).json({ error: "Missing handle" });

    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });
    const scanLevel = deepScan ? "Perform a rigorous, multi-step analysis" : "Perform a standard analysis";

    const prompt = `
      You are an expert at detecting bot behavior and synthetic identities on social media.
      ${scanLevel} on the social media handle: ${handle}.
      Since you cannot browse live, simulate a likely analysis for this type of handle based on common bot patterns.
      
      Respond STRICTLY with a raw JSON object (no markdown, no backticks).
      {
        "aiProbability": <number between 0 and 100>,
        "trustScore": <number between 0 and 100>,
        "status": "<exactly 'Authentic' or 'AI Generated/Bot'>",
        "explanation": "<1-2 sentence explanation>"
      }
    `;

    const aiResult = await model.generateContent(prompt);
    let rawText = aiResult.response.text().replace(/```json/gi, "").replace(/```/g, "").trim();
    const aiData = JSON.parse(rawText);

    const trustScoreNum = Number(aiData.trustScore) || 50;
    const aiProbNum = 100 - trustScoreNum;

    const scanRecord = new Scan({
      userId: req.user.id,
      aiProbability: aiProbNum.toString() + "%",
      trustScore: trustScoreNum.toString() + "%",
      status: aiData.status,
      explanation: aiData.explanation,
      filename: handle,
      mediaType: "social-profile",
    });

    await scanRecord.save();

    res.json({
      aiProbability: aiProbNum.toString() + "%",
      trustScore: trustScoreNum.toString() + "%",
      status: aiData.status,
      explanation: aiData.explanation,
    });
  } catch (error) {
    console.error("Social Scan Error:", error);
    res.status(500).json({ error: "Failed to analyze social profile." });
  }
});

// ================================
// ANALYZE DOCUMENT
// ================================
app.post('/analyze-document', authenticateToken, upload.single('document'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No document uploaded" });
    
    const deepScan = req.body.deepScan === 'true';
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });
    const fileMimeType = req.file.mimetype;
    
    // Upload document to Gemini (Gemini supports pdf and text)
    const fileManager = new GoogleAIFileManager(process.env.GEMINI_API_KEY);
    const uploadResponse = await fileManager.uploadFile(req.file.path, {
      mimeType: fileMimeType,
      displayName: req.file.originalname,
    });
    
    let fileState = await fileManager.getFile(uploadResponse.file.name);
    while (fileState.state === 'PROCESSING') {
      await new Promise((resolve) => setTimeout(resolve, 3000));
      fileState = await fileManager.getFile(uploadResponse.file.name);
    }
    
    if (fileState.state === 'FAILED') {
      throw new Error('Document processing failed.');
    }

    const scanLevel = deepScan ? "Perform a rigorous, multi-step deep scan analysis" : "Perform a standard analysis";
    const prompt = `
      You are an expert at detecting AI-generated text in documents (PDF/Word/Txt).
      ${scanLevel} on the uploaded document.
      
      Respond STRICTLY with a raw JSON object (no markdown, no backticks).
      {
        "aiProbability": <number between 0 and 100>,
        "trustScore": <number between 0 and 100>,
        "status": "<exactly 'Authentic' or 'AI Generated'>",
        "explanation": "<1-2 sentence explanation>"
      }
    `;

    const aiResult = await model.generateContent([
      prompt,
      { fileData: { mimeType: uploadResponse.file.mimeType, fileUri: uploadResponse.file.uri } }
    ]);
    
    let rawText = aiResult.response.text().replace(/```json/gi, "").replace(/```/g, "").trim();
    const aiData = JSON.parse(rawText);

    const trustScoreNum = Number(aiData.trustScore) || 50;
    const aiProbNum = 100 - trustScoreNum;

    const scanRecord = new Scan({
      userId: req.user.id,
      aiProbability: aiProbNum.toString() + "%",
      trustScore: trustScoreNum.toString() + "%",
      status: aiData.status,
      explanation: aiData.explanation,
      filename: req.file.originalname,
      mediaType: "document",
    });

    await scanRecord.save();

    res.json({
      aiProbability: aiProbNum.toString() + "%",
      trustScore: trustScoreNum.toString() + "%",
      status: aiData.status,
      explanation: aiData.explanation,
    });
    
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
  } catch (error) {
    console.error("Document Scan Error:", error);
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: "Failed to analyze document." });
  }
});

// ================================
// ANALYZE LIVE AUDIO (Mocked for Deepfake Check)
// ================================
app.post("/analyze-live-audio", authenticateToken, async (req, res) => {
  try {
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });
    const prompt = `
You are an expert audio forensics AI. A user just recorded a 5-second ambient audio clip in a live setting.
Generate a realistic JSON report analyzing this audio for deepfake synthesis artifacts, background noise consistency, and vocal tract modeling anomalies.
Return ONLY a raw JSON object without markdown formatting.
Format:
{
  "aiProbability": "<number between 0 and 100>",
  "trustScore": "<number between 0 and 100, where trustScore = 100 - aiProbability>",
  "status": "<exactly 'Authentic' or 'AI Generated'>",
  "explanation": "<1-2 sentence explanation of the audio artifacts found or absence thereof>"
}
    `;

    const result = await model.generateContent(prompt);
    let rawText = result.response.text().replace(/```json/gi, "").replace(/```/g, "").trim();
    const aiData = JSON.parse(rawText);

    const trustScoreNum = Number(aiData.trustScore) || 50;
    const aiProbNum = Number(aiData.aiProbability) || (100 - trustScoreNum);

    const scanRecord = new Scan({
      userId: req.user.id,
      aiProbability: aiProbNum.toString() + "%",
      trustScore: trustScoreNum.toString() + "%",
      status: aiData.status,
      explanation: aiData.explanation,
      filename: "Live_Audio_Recording",
      mediaType: "audio",
    });

    await scanRecord.save();

    res.json({
      aiProbability: aiProbNum.toString() + "%",
      trustScore: trustScoreNum.toString() + "%",
      status: aiData.status,
      explanation: aiData.explanation,
    });
  } catch (error) {
    console.error("Live Audio Scan Error:", error);
    res.status(500).json({ error: "Failed to analyze live audio." });
  }
});

// ================================
// ANALYZE URL (Scrape + Gemini)
// ================================
app.post("/analyze-url", authenticateToken, async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "Missing url" });

    // 1. Fetch webpage content
    const pageResponse = await axios.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      },
      timeout: 10000
    });

    // 2. Extract text using cheerio
    const $ = cheerio.load(pageResponse.data);
    
    // Remove scripts and styles
    $('script, style, noscript, iframe, img, svg').remove();
    
    // Get raw text
    let pageText = $('body').text().replace(/\s+/g, ' ').trim();
    
    // Truncate to reasonable length for Gemini (e.g., first 15000 characters)
    if (pageText.length > 15000) {
      pageText = pageText.substring(0, 15000) + '...';
    }
    
    if (pageText.length < 50) {
      return res.status(400).json({ error: "Could not extract enough readable text from the URL." });
    }

    // 3. Send to Gemini
    const model = genAI.getGenerativeModel({
      model: "gemini-2.5-flash-lite",
    });

    const prompt = `
      You are an expert at detecting AI-generated content, fake news, and misinformation.
      Analyze the following text extracted from a webpage (${url}).
      
      Website Text:
      "${pageText}"

      Determine if the content is likely Authentic (human-written, factual reporting) or AI Generated (synthetic, bot-written, deepfake news, hallucinatory).
      
      Respond STRICTLY with a raw JSON object (no markdown, no backticks).
      {
        "aiProbability": <number between 0 and 100>,
        "trustScore": <number between 0 and 100>,
        "status": "<exactly 'Authentic' or 'AI Generated'>",
        "explanation": "<1-2 sentence explanation>"
      }
    `;

    const aiResult = await model.generateContent(prompt);
    const responseText = aiResult.response.text();
    let jsonMatch = responseText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error("Failed to parse JSON from AI response");
    }
    const aiData = JSON.parse(jsonMatch[0]);

    const trustScoreNum = Number(aiData.trustScore) || 50;
    const aiProbNum = 100 - trustScoreNum;

    // 4. Save scan to history
    const scanRecord = new Scan({
      userId: req.user.id,
      aiProbability: aiProbNum.toString() + "%",
      trustScore: trustScoreNum.toString() + "%",
      status: aiData.status,
      explanation: aiData.explanation,
      filename: url,
      mediaType: "url-scrape",
    });

    await scanRecord.save();

    res.json({
      aiProbability: aiProbNum.toString() + "%",
      trustScore: trustScoreNum.toString() + "%",
      status: aiData.status,
      explanation: aiData.explanation,
    });
  } catch (error) {
    console.error("URL Scrape Error:", error.message);
    res.status(500).json({ error: "Failed to analyze URL content." });
  }
});

// ================================
// DYNAMIC GENERATION APIs (Powered by Gemini)
// ================================

app.get('/feed', authenticateToken, async (req, res) => {
  try {
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });
    const prompt = `
Generate 3 realistic community feed posts for a deepfake detection app called "TruthPulse".
Return ONLY a raw JSON array of objects without markdown formatting.
Each object must have:
- author (string, e.g. "@CyberSleuth")
- title (string)
- content (string)
- upvotes (number)
- aiProbability (number between 0 and 100)
- comments (an array of 1 to 3 objects, each having "user" and "text" string fields)
- imageUrl (optional string, generate a valid url exactly like "https://picsum.photos/seed/[random_word]/800/600" replacing [random_word] with a random 5-letter word, mix of present and null)
`;
    const result = await model.generateContent(prompt);
    let rawText = result.response.text().replace(/```json/gi, "").replace(/```/g, "").trim();
    const posts = JSON.parse(rawText);
    res.json(posts);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to generate community feed" });
  }
});

app.get('/quiz', authenticateToken, async (req, res) => {
  try {
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });
    const prompt = `
Generate 3 realistic quiz questions for spotting deepfakes/AI.
Return ONLY a raw JSON array of objects without markdown formatting.
Each object must have:
- imageUrl (string, generate a valid url exactly like "https://picsum.photos/seed/[random_word]/800/600" replacing [random_word] with a random 5-letter word)
- isAiGenerated (boolean)
- explanation (string, explaining why it is or isn't AI generated based on typical tells)
`;
    const result = await model.generateContent(prompt);
    let rawText = result.response.text().replace(/```json/gi, "").replace(/```/g, "").trim();
    const questions = JSON.parse(rawText);
    res.json(questions);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to generate quiz questions" });
  }
});

app.get('/news', authenticateToken, async (req, res) => {
  try {
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });
    const prompt = `
Generate 5 realistic news headlines and short subtitles about AI, deepfakes, and cybersecurity.
Return ONLY a raw JSON array of objects without markdown formatting.
Each object must have:
- title (string, headline)
- subtitle (string, short summary)
`;
    const result = await model.generateContent(prompt);
    let rawText = result.response.text().replace(/```json/gi, "").replace(/```/g, "").trim();
    const news = JSON.parse(rawText);
    res.json(news);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to generate news" });
  }
});

app.get('/learning', authenticateToken, async (req, res) => {
  try {
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });
    const prompt = `
Generate 4 realistic learning hub articles about deepfake detection.
Return ONLY a raw JSON array of objects without markdown formatting.
Each object must have:
- title (string)
- content (string, a 3-paragraph article with tips on spotting AI)
- iconType (string, e.g. "school", "article", "shield")
`;
    const result = await model.generateContent(prompt);
    let rawText = result.response.text().replace(/```json/gi, "").replace(/```/g, "").trim();
    const articles = JSON.parse(rawText);
    res.json(articles);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to generate learning content" });
  }
});


// ================================
// START SERVER
// ================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
