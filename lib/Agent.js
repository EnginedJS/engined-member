const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const PermissionManager = require('../lib/PermissionManager');
const MemberManager = require('../lib/MemberManager');
const RelationalMap = require('./RelationalMap');

module.exports = class Agent {

	constructor(service) {
		this.service = service;
		this.dbAgent = service.dbAgent;
		this.permissionManager = new PermissionManager(this);
		this.memberManager = new MemberManager(this);

		// Options
		this.options = Object.assign({
			agentName: 'default',
			httpAgent: 'default',
			dbAgent: 'default',
			storageAgent: 'default',
			expiresIn: 30 * 24 * 60 * 60 * 1000,
			secret: '',
			signInUrl: '/signin',
			accountIsDisabledByDefault: false
		}, service.opts);

		// Initializing data models
		this.dataModel = service.dataModel;
		this.dataMap = new RelationalMap();
		this.dataMap.applyDbSchema(this.dataModel.database.getModels());
		this.dataMap.applyViewSchema(this.dataModel.view.getModels());
	}

	getView(viewName) {
		return this.dataMap.getView(viewName);
	}

	getValidationRules(name) {
		return this.dataModel.validation.getModel(name);
	}

	generateSalt() {
		return crypto.randomBytes(12).toString('base64');
	}

	generateJwtToken(payload, expiresIn) {

		// Packing token
		return jwt.sign(payload, this.options.secret, {
			expiresIn: expiresIn || this.options.expiresIn
		}, { algorithm: 'HS512' });
	}

	decodeJwtToken(token) {
		return jwt.verify(token, this.options.secret);
	}

	encryptPassword(salt, password) {
		return crypto.createHmac('sha256', password + salt || '').digest('hex');
	}

	getContext() {
		return this.service.getContext();
	}

	getOptions() {
		return this.options;
	}

	getMemberSchema() {
		return this.options.memberSchema;
	}

	getSchemaChecker(name) {
		// TODO: implement memoization to improve performance
		return this.options.schemaChecker[name](this.options.memberSchema);
	}

	getMemberManager() {
		return this.memberManager;
	}

	getPermissionManager() {
		return this.permissionManager;
	}

	getPermissionMiddleware() {
		return this.permissionManager.getMiddleware();
	}
};
