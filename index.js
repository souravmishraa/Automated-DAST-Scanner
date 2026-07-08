'use strict';

module.exports = {
  runScan: require('./core').runScan,
  computeExitCode: require('./core').computeExitCode,
  loadConfig: require('./core/configLoader').loadConfig,
  validate: require('./core/configLoader').validate,
  isValidUrl: require('./core/configLoader').isValidUrl,
  generateReports: require('./core/reporter').generateReports,
  AuthManager: require('./core/auth/authManager').AuthManager,
  KatanaRunner: require('./core/crawler/katanaRunner').KatanaRunner,
  SwaggerDiscovery: require('./core/crawler/swaggerDiscovery').SwaggerDiscovery,
  ZapRunner: require('./core/zap/zapRunner').ZapRunner,
  NucleiRunner: require('./core/nuclei/nucleiRunner').NucleiRunner,
  normalizeAll: require('./core/normalizer/normalizer').normalizeAll
};
