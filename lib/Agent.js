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

	Permission(permPath) {

		// Parsing permission path
		let perm = this.getPermissionManager().parsePermissionPath(permPath);
		let permInfo = this.service.perms[perm.groupName][perm.signature];
		if (!permInfo) {
			throw new Error('No such permission: ' + permPath);
		}

		return async (ctx, next) => {

			// User doens't have this permission
			if (ctx.state.session.perms.indexOf(permPath) === -1) {

				// redirect or customized process
				if (permInfo.reject) {
					return await permInfo.reject(ctx, next);
				}

				return await this.service.defaultReject(ctx, next);
			}

			// do something to check permission
			if (permInfo.approve) {
				return await permInfo.approve(ctx, next);
			}

			await next();
		};
	}
};
