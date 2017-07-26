const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const PermissionAPI = require('../lib/Permission');

module.exports = class Agent {

	constructor(service) {
		this.service = service;
		this.dbAgentName = service.dbAgentName;
		this.permissionManager = PermissionAPI(this.service);
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

	getPermissionManager() {
		return this.permissionManager;
	}

	Permission(permPath) {

		// Parsing permission path
		let perm = this.getPermissionManager().parsePermissionPath(permPath);
		let permInfo = this.perms[perm.groupName][perm.signature];
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

				return await this.defaultReject(ctx, next);
			}

			// do something to check permission
			if (permInfo.approve) {
				return await permInfo.approve(ctx, next);
			}

			await next();
		};
	}
};
