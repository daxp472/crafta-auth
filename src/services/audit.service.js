const AuditLog = require('../models/audit-log');
const winston = require('winston');

class AuditService {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.File({ filename: 'audit.log' })
      ]
    });
  }

  async logActivity(data) {
    const log = new AuditLog({
      userId: data.userId,
      action: data.action,
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      details: data.details,
      status: data.status
    });

    await log.save();
    this.logger.info('Activity logged', { logId: log._id, ...data });
    return log;
  }

  async getUserActivity(userId, filters = {}) {
    const query = { userId, ...filters };
    return AuditLog.find(query).sort({ timestamp: -1 });
  }

  async getActivityByDateRange(startDate, endDate) {
    return AuditLog.find({
      timestamp: {
        $gte: startDate,
        $lte: endDate
      }
    }).sort({ timestamp: -1 });
  }

  async getFailedLoginAttempts(userId, timeWindow) {
    const since = new Date(Date.now() - timeWindow);
    return AuditLog.countDocuments({
      userId,
      action: 'login',
      status: 'failure',
      timestamp: { $gte: since }
    });
  }

  /**
   * Returns login attempt analytics including success rate, top failure reasons,
   * and time-based patterns (hourly breakdown).
   * @param {Object} filters - Optional filters like startDate, endDate, userId
   */
  async getLoginAttemptAnalytics(filters = {}) {
    const query = { action: 'login' };
    if (filters.userId) {
      query.userId = filters.userId;
    }
    if (filters.startDate || filters.endDate) {
      query.timestamp = {};
      if (filters.startDate) query.timestamp.$gte = new Date(filters.startDate);
      if (filters.endDate) query.timestamp.$lte = new Date(filters.endDate);
    }

    const totalAttempts = await AuditLog.countDocuments(query);
    const successfulAttempts = await AuditLog.countDocuments({ ...query, status: 'success' });
    const failedAttempts = await AuditLog.countDocuments({ ...query, status: 'failure' });

    const successRate = totalAttempts > 0
      ? Number(((successfulAttempts / totalAttempts) * 100).toFixed(2))
      : 0;

    // Top failure reasons from details.error
    const topFailures = await AuditLog.aggregate([
      { $match: { ...query, status: 'failure' } },
      { $group: { _id: { $ifNull: ['$details.error', 'Unknown reason'] }, count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 5 },
      { $project: { reason: '$_id', count: 1, _id: 0 } }
    ]);

    // Time-based patterns: hourly distribution (0-23)
    const timeBasedPatterns = await AuditLog.aggregate([
      { $match: query },
      {
        $group: {
          _id: { $hour: '$timestamp' },
          total: { $sum: 1 },
          success: { $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] } },
          failure: { $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] } }
        }
      },
      { $sort: { _id: 1 } },
      {
        $project: {
          hour: '$_id',
          total: 1,
          success: 1,
          failure: 1,
          _id: 0
        }
      }
    ]);

    return {
      totalAttempts,
      successfulAttempts,
      failedAttempts,
      successRate: `${successRate}%`,
      topFailures,
      timeBasedPatterns
    };
  }
}

module.exports = AuditService;