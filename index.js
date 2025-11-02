// app.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const ipInfo = require('ipinfo');
const UAParser = require('ua-parser-js');
const app = express();
const port = process.env.PORT || 3000;
const IPINFO_TOKEN = process.env.IPINFO_TOKEN;

// Middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Enhanced schema for request logs with comprehensive user details
const requestLogSchema = new mongoose.Schema({
  // Basic Request Info
  method: String,
  url: String,
  fullUrl: String,
  ip: String,
  forwardedIps: [String], // Track proxy chains
  userAgent: String,
  headers: Object,
  queryParams: Object,
  body: Object,
  responseStatus: Number,
  responseTime: Number,
  
  // Enhanced Geolocation Data
  location: {
    country: { type: String },
    countryCode: { type: String },
    region: { type: String },
    regionCode: { type: String },
    city: { type: String },
    postalCode: { type: String },
    latitude: { type: String },
    longitude: { type: String },
    timezone: { type: String },
    continent: { type: String },
    accuracyRadius: { type: Number }
  },
  
  // Network & Security Info
  network: {
    asn: { type: String },
    asnOrg: { type: String },
    isp: { type: String },
    domain: { type: String },
    isVPN: { type: Boolean },
    isProxy: { type: Boolean },
    isTor: { type: Boolean },
    isHosting: { type: Boolean },
    isRelay: { type: Boolean }
  },
  
  // Enhanced Device Info
  device: {
    type: { type: String }, // mobile, tablet, desktop, wearable, tv, etc.
    model: { type: String },
    vendor: { type: String },
    architecture: { type: String },
    isBot: { type: Boolean },
    isMobile: { type: Boolean },
    isTablet: { type: Boolean },
    isDesktop: { type: Boolean },
    isTouchCapable: { type: Boolean }
  },
  
  // Operating System Details
  os: {
    name: { type: String },
    version: { type: String },
    platform: { type: String },
    fullVersion: { type: String }
  },
  
  // Browser Details
  browser: {
    name: { type: String },
    version: { type: String },
    major: { type: String },
    engine: { type: String },
    engineVersion: { type: String },
    isChromium: { type: Boolean },
    cookiesEnabled: { type: Boolean },
    doNotTrack: { type: Boolean },
    language: { type: String },
    languages: [{ type: String }]
  },
  
  // Screen & Display Info (from headers/client hints)
  display: {
    screenResolution: { type: String },
    viewportSize: { type: String },
    colorDepth: { type: Number },
    pixelRatio: { type: Number }
  },
  
  // Connection Info
  connection: {
    protocol: { type: String }, // http/https
    httpVersion: { type: String },
    secure: { type: Boolean },
    referrer: { type: String },
    origin: { type: String },
    acceptLanguage: { type: String },
    acceptEncoding: { type: String },
    cacheControl: { type: String }
  },
  
  // Session & Tracking
  session: {
    cookies: { type: Object },
    sessionId: { type: String },
    fingerprint: { type: String } // Generated hash for tracking
  },
  
  // Request Metadata
  metadata: {
    isAjax: { type: Boolean },
    contentType: { type: String },
    contentLength: { type: Number },
    method: { type: String },
    path: { type: String },
    host: { type: String },
    port: { type: Number }
  },
  
  timestamp: { type: Date, default: Date.now },
  
  // Additional computed fields
  requestDay: String, // Monday, Tuesday, etc.
  requestHour: Number,
  isWeekend: Boolean,
  timeSinceLastRequest: Number // Milliseconds since last request from this IP
});

// Add indexes for better query performance
requestLogSchema.index({ ip: 1, timestamp: -1 });
requestLogSchema.index({ timestamp: -1 });
requestLogSchema.index({ 'session.fingerprint': 1 });

const RequestLog = mongoose.model('RequestLog', requestLogSchema);

// Helper function to generate device fingerprint
function generateFingerprint(req, ipData, deviceInfo) {
  const crypto = require('crypto');
  const fingerprintData = [
    req.ip,
    req.get('User-Agent'),
    ipData?.timezone || '',
    deviceInfo.vendor || '',
    req.get('Accept-Language') || ''
  ].join('|');
  
  return crypto.createHash('md5').update(fingerprintData).digest('hex');
}

// Helper function to detect if request is from a bot
function isBot(userAgent) {
  const botPatterns = /bot|crawl|slurp|spider|mediapartners|headless|phantom|selenium/i;
  return botPatterns.test(userAgent);
}

// Helper function to extract real IP considering proxies
function extractRealIp(req) {
  const forwardedFor = req.get('X-Forwarded-For');
  const realIp = req.get('X-Real-IP');
  const cfConnectingIp = req.get('CF-Connecting-IP'); // Cloudflare
  
  let ip = req.ip || req.connection.remoteAddress;
  let forwardedIps = [];
  
  if (cfConnectingIp) {
    ip = cfConnectingIp;
  } else if (realIp) {
    ip = realIp;
  } else if (forwardedFor) {
    forwardedIps = forwardedFor.split(',').map(ip => ip.trim());
    ip = forwardedIps[0]; // First IP is usually the real client
  }
  
  // Clean IPv6 prefix if present
  ip = ip.replace(/^::ffff:/, '');
  
  return { ip, forwardedIps };
}

// Enhanced middleware to log requests with comprehensive user details
app.use(async (req, res, next) => {
  const start = Date.now();

  res.on('finish', async () => {
    const responseTime = Date.now() - start;
    const { ip, forwardedIps } = extractRealIp(req);
    const userAgent = req.get('User-Agent') || 'Unknown';
    
    // Initialize log data
    const logData = {
      method: req.method,
      url: req.originalUrl,
      fullUrl: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
      ip,
      forwardedIps,
      userAgent,
      headers: req.headers,
      queryParams: req.query,
      body: req.body,
      responseStatus: res.statusCode,
      responseTime
    };

    // Parse detailed device, OS, and browser info
    const parser = new UAParser(userAgent);
    const deviceInfo = parser.getDevice();
    const osInfo = parser.getOS();
    const browserInfo = parser.getBrowser();
    const engineInfo = parser.getEngine();
    const cpuInfo = parser.getCPU();

    // Device details
    logData.device = {
      type: deviceInfo.type || 'desktop',
      model: deviceInfo.model || 'Unknown',
      vendor: deviceInfo.vendor || 'Unknown',
      architecture: cpuInfo.architecture || 'Unknown',
      isBot: isBot(userAgent),
      isMobile: deviceInfo.type === 'mobile',
      isTablet: deviceInfo.type === 'tablet',
      isDesktop: !deviceInfo.type || deviceInfo.type === 'desktop',
      isTouchCapable: deviceInfo.type === 'mobile' || deviceInfo.type === 'tablet'
    };

    // OS details
    logData.os = {
      name: osInfo.name || 'Unknown',
      version: osInfo.version || 'Unknown',
      platform: cpuInfo.architecture || 'Unknown',
      fullVersion: `${osInfo.name || 'Unknown'} ${osInfo.version || ''}`
    };

    // Browser details
    const isChromium = browserInfo.name && 
      (browserInfo.name.includes('Chrome') || 
       browserInfo.name.includes('Edge') || 
       browserInfo.name.includes('Opera'));
    
    logData.browser = {
      name: browserInfo.name || 'Unknown',
      version: browserInfo.version || 'Unknown',
      major: browserInfo.major || 'Unknown',
      engine: engineInfo.name || 'Unknown',
      engineVersion: engineInfo.version || 'Unknown',
      isChromium,
      cookiesEnabled: req.get('Cookie') ? true : false,
      doNotTrack: req.get('DNT') === '1',
      language: req.get('Accept-Language')?.split(',')[0] || 'Unknown',
      languages: req.get('Accept-Language')?.split(',').map(l => l.trim().split(';')[0]) || []
    };

    // Connection info
    logData.connection = {
      protocol: req.protocol,
      httpVersion: req.httpVersion,
      secure: req.secure,
      referrer: req.get('Referer') || req.get('Referrer') || 'Direct',
      origin: req.get('Origin') || 'Unknown',
      acceptLanguage: req.get('Accept-Language') || 'Unknown',
      acceptEncoding: req.get('Accept-Encoding') || 'Unknown',
      cacheControl: req.get('Cache-Control') || 'None'
    };

    // Display info from client hints if available
    logData.display = {
      screenResolution: req.get('Sec-CH-Viewport-Width') && req.get('Sec-CH-Viewport-Height') 
        ? `${req.get('Sec-CH-Viewport-Width')}x${req.get('Sec-CH-Viewport-Height')}`
        : 'Unknown',
      viewportSize: req.get('Sec-CH-Viewport-Width') || 'Unknown',
      colorDepth: parseInt(req.get('Sec-CH-Color-Depth')) || 0,
      pixelRatio: parseFloat(req.get('Sec-CH-DPR')) || 1.0
    };

    // Metadata
    logData.metadata = {
      isAjax: req.xhr || req.get('X-Requested-With') === 'XMLHttpRequest',
      contentType: req.get('Content-Type') || 'None',
      contentLength: parseInt(req.get('Content-Length')) || 0,
      method: req.method,
      path: req.path,
      host: req.hostname,
      port: req.get('host')?.split(':')[1] || (req.secure ? 443 : 80)
    };

    // Get enhanced geolocation and network/security info
    let ipData = null;
    try {
      ipData = await ipInfo(ip, IPINFO_TOKEN);
      
      // Enhanced location data
      logData.location = {
        country: ipData.country || 'Unknown',
        countryCode: ipData.country || 'Unknown',
        region: ipData.region || 'Unknown',
        regionCode: ipData.region || 'Unknown',
        city: ipData.city || 'Unknown',
        postalCode: ipData.postal || 'Unknown',
        latitude: ipData.loc?.split(',')[0] || 'Unknown',
        longitude: ipData.loc?.split(',')[1] || 'Unknown',
        timezone: ipData.timezone || 'Unknown',
        continent: ipData.continent?.name || 'Unknown',
        accuracyRadius: 0
      };

      // Network and security info
      logData.network = {
        asn: ipData.asn?.asn || 'Unknown',
        asnOrg: ipData.asn?.name || ipData.org || 'Unknown',
        isp: ipData.org || 'Unknown',
        domain: ipData.asn?.domain || 'Unknown',
        isVPN: ipData.privacy?.vpn || false,
        isProxy: ipData.privacy?.proxy || false,
        isTor: ipData.privacy?.tor || false,
        isHosting: ipData.privacy?.hosting || false,
        isRelay: ipData.privacy?.relay || false
      };
    } catch (geoErr) {
      console.error('Error fetching geolocation data:', geoErr.message);
      logData.location = {
        country: 'Unknown',
        countryCode: 'Unknown',
        region: 'Unknown',
        regionCode: 'Unknown',
        city: 'Unknown',
        postalCode: 'Unknown',
        latitude: 'Unknown',
        longitude: 'Unknown',
        timezone: 'Unknown',
        continent: 'Unknown',
        accuracyRadius: 0
      };
      logData.network = {
        asn: 'Unknown',
        asnOrg: 'Unknown',
        isp: 'Unknown',
        domain: 'Unknown',
        isVPN: false,
        isProxy: false,
        isTor: false,
        isHosting: false,
        isRelay: false
      };
    }

    // Session tracking
    const fingerprint = generateFingerprint(req, ipData, deviceInfo);
    logData.session = {
      cookies: req.cookies || {},
      sessionId: req.sessionID || req.get('X-Session-ID') || 'None',
      fingerprint
    };

    // Time-based analytics
    const now = new Date();
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    logData.requestDay = days[now.getDay()];
    logData.requestHour = now.getHours();
    logData.isWeekend = now.getDay() === 0 || now.getDay() === 6;

    // Calculate time since last request from this IP
    try {
      const lastLog = await RequestLog.findOne({ ip }).sort({ timestamp: -1 });
      if (lastLog) {
        logData.timeSinceLastRequest = Date.now() - lastLog.timestamp.getTime();
      } else {
        logData.timeSinceLastRequest = 0;
      }
    } catch (err) {
      logData.timeSinceLastRequest = 0;
    }

    // Save log
    const log = new RequestLog(logData);
    try {
      await log.save();
      console.log(`Request logged: ${req.method} ${req.originalUrl} from ${ip} [${logData.location.city}, ${logData.location.country}]`);
    } catch (err) {
      console.error('Error logging request:', err.message);
    }
  });

  next();
});

// Sample GET endpoint
app.get('/api/hello', (req, res) => {
  res.status(200).json({ message: 'Hello, World!' });
});

// Sample POST endpoint
app.post('/api/data', (req, res) => {
  const { name, value } = req.body;
  if (!name || !value) {
    return res.status(400).json({ error: 'Name and value are required' });
  }
  res.status(201).json({ message: 'Data received', data: { name, value } });
});

// Enhanced endpoint to retrieve logs with filtering
app.get('/api/private/logs', async (req, res) => {
  try {
    const { limit = 100, country, isVPN, device, sortBy = 'timestamp' } = req.query;
    
    const filter = {};
    if (country) filter['location.country'] = country;
    if (isVPN !== undefined) filter['network.isVPN'] = isVPN === 'true';
    if (device) filter['device.type'] = device;
    
    const logs = await RequestLog.find(filter)
      .sort({ [sortBy]: -1 })
      .limit(parseInt(limit));
    
    res.status(200).json(logs);
  } catch (err) {
    console.error('Error retrieving logs:', err.message);
    res.status(500).json({ error: 'Failed to retrieve logs' });
  }
});

// New endpoint: Get user analytics by IP
app.get('/api/private/analytics/ip/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    const logs = await RequestLog.find({ ip }).sort({ timestamp: -1 });
    
    const analytics = {
      totalRequests: logs.length,
      firstSeen: logs[logs.length - 1]?.timestamp,
      lastSeen: logs[0]?.timestamp,
      devices: [...new Set(logs.map(l => l.device.type))],
      browsers: [...new Set(logs.map(l => l.browser.name))],
      locations: [...new Set(logs.map(l => `${l.location.city}, ${l.location.country}`))],
      isVPN: logs[0]?.network.isVPN,
      endpoints: logs.map(l => ({ method: l.method, url: l.url, status: l.responseStatus }))
    };
    
    res.status(200).json(analytics);
  } catch (err) {
    console.error('Error generating analytics:', err.message);
    res.status(500).json({ error: 'Failed to generate analytics' });
  }
});

// New endpoint: Get overall analytics dashboard
app.get('/api/private/analytics/dashboard', async (req, res) => {
  try {
    const logs = await RequestLog.find().sort({ timestamp: -1 }).limit(1000);
    
    const analytics = {
      totalRequests: logs.length,
      uniqueIPs: new Set(logs.map(l => l.ip)).size,
      uniqueFingerprints: new Set(logs.map(l => l.session.fingerprint)).size,
      topCountries: getTopN(logs.map(l => l.location.country), 5),
      topDevices: getTopN(logs.map(l => l.device.type), 5),
      topBrowsers: getTopN(logs.map(l => l.browser.name), 5),
      vpnPercentage: ((logs.filter(l => l.network.isVPN).length / logs.length) * 100).toFixed(2),
      botPercentage: ((logs.filter(l => l.device.isBot).length / logs.length) * 100).toFixed(2),
      avgResponseTime: (logs.reduce((sum, l) => sum + l.responseTime, 0) / logs.length).toFixed(2),
      requestsByHour: getRequestsByHour(logs),
      requestsByDay: getRequestsByDay(logs)
    };
    
    res.status(200).json(analytics);
  } catch (err) {
    console.error('Error generating dashboard:', err.message);
    res.status(500).json({ error: 'Failed to generate dashboard' });
  }
});

// Helper function to get top N occurrences
function getTopN(arr, n) {
  const counts = {};
  arr.forEach(item => counts[item] = (counts[item] || 0) + 1);
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([item, count]) => ({ item, count }));
}

// Helper function to get requests by hour
function getRequestsByHour(logs) {
  const hourCounts = Array(24).fill(0);
  logs.forEach(log => hourCounts[log.requestHour]++);
  return hourCounts.map((count, hour) => ({ hour, count }));
}

// Helper function to get requests by day
function getRequestsByDay(logs) {
  const dayCounts = {};
  const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  days.forEach(day => dayCounts[day] = 0);
  logs.forEach(log => dayCounts[log.requestDay]++);
  return Object.entries(dayCounts).map(([day, count]) => ({ day, count }));
}

// Start server
app.listen(port, () => {
  console.log(`Enhanced RequestTrace running at http://localhost:${port}`);
  console.log(`Available endpoints:`);
  console.log(`  - GET  /api/hello`);
  console.log(`  - POST /api/data`);
  console.log(`  - GET  /api/logs`);
  console.log(`  - GET  /api/analytics/ip/:ip`);
  console.log(`  - GET  /api/analytics/dashboard`);
});