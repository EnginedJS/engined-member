const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const PermissionManager = require('../lib/PermissionManager');
const MemberManager = require('../lib/MemberManager');

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
			expiresIn: 30 * 24 * 60 * 60 * 1000,
			secret: '',
			signInUrl: '/signin',
			accountIsDisabledByDefault: false,
			memberSchema: Joi.object().keys({
				email: Joi.string().email(),
				password: Joi.string(),
				name: Joi.string()
			}),
			schemaChecker: {
				createMember: (schema) => {
					return schema.requiredKeys('email', 'password', 'name');
				},
				verify: (schema) => {
					return schema.requiredKeys('email', 'password')
				}
			}
		}, service.opts);
	}

	generateSalt() {
		return crypto.randomBytes(12).toString('base64');
	}

	generateJwtToken(payload) {

		// Packing token
		return jwt.sign(payload, this.options.secret, {
			expiresIn: this.options.expiresIn
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
