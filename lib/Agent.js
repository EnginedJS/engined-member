const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const PermissionAPI = require('../lib/Permission');

module.exports = class Agent {

	constructor(service) {
		this.service = service;
		this.dbAgent = service.dbAgent;
		this.permissionManager = PermissionAPI(this.service);
		this.options = Object.assign({
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
		return jwt.sign(payload, this.service.secret, {
			expiresIn: this.expiresIn
		}, { algorithm: 'HS512' });
	}

	decodeJwtToken(token) {
		return jwt.verify(token, this.service.secret);
	}

	encryptPassword(salt, password) {
		return crypto.createHmac('sha256', password + salt || '').digest('hex');
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

	getPermissionManager() {
		return this.permissionManager;
	}

	getPermissionMiddleware() {
		return this.permissionManager.getMiddleware();
	}
};
