class PermissionHandler {

	constructor(groupName, signature, description) {

		this.groupName = groupName;
		this.signature = signature;
		this.description = description;
		this.handlers = {};
	}

	check(handler) {
		this.handlers.check = handler
	}

	approve(handler) {
		this.handlers.approve = handler
	}

	reject(handler) {
		this.handlers.reject = handler
	}
}

module.exports = class {

	constructor(memberAgent) {
		this.memberAgent = memberAgent;
		this.perms = {};
		this.defaultHandlers = {
			reject: async (ctx, next) => {

				if (ctx.state.routeType === 'API') {
					// Forbbiden
					ctx.throw(403);
				} else {
					// Redirect to login page
					ctx.redirect(memberAgent.options.signInUrl);
				}
			}
		};
	}

	registerPermission(groupName, signature, descriptor, approve, reject) {

		if (this.perms[groupName] === undefined)
			this.perms[groupName] = {};

		if (this.perms[groupName][signature] !== undefined) {
			throw new Error('Permission \"' + groupName + '.' + signature + '\" exists already');
		}

		// Create a new permission handler
		let handler = new PermissionHandler(groupName, signature, descriptor);

		this.perms[groupName][signature] = handler;

		return handler;
	}

	unregisterPermission(groupName, signature) {
		if (this.perms[groupName] === undefined)
			return;

		if (this.perms[groupName][signature] === undefined)
			return;

		delete this.perms[groupName][signature];
	}

	unregisterPermissionGroup(groupName) {
		if (this.perms[groupName] === undefined)
			return;

		delete this.perms[groupName];
	}

	parsePermissionPath(permPath) {

		let parts = permPath.split('.');
		let groupName = parts.shift();
		let signature = parts.join('.');

		return {
			groupName: groupName,
			signature: signature
		}
	}

	async addPermission(memberId, permissions) {

		// Getting database agent
		const dbAgent = this.memberAgent.getContext().get('MySQL').getAgent(this.memberAgent.options.dbAgent);

		try {
			// Preparing permission records
			let values = permissions.map((permPath) => {

				let perm = this.parsePermissionPath(permPath);

				return [
					memberId,
					perm.groupName,
					perm.signature
				];
			});

			let qstr = [
				'INSERT INTO `MemberPermission` (`member`, `groupName`, `signature`) VALUES ?'
			].join(' ');

			let [ ret ] = await dbAgent.query(qstr, [ values ]);
		} catch(e) {

			// permission exists already
			if (e.code === 'ER_DUP_ENTRY') {
				// Do nothing
			} else {
				throw e;
			}
		}
	}

	async getPermissions(memberId) {

		// Getting database agent
		const dbAgent = this.memberAgent.getContext().get('MySQL').getAgent(this.memberAgent.options.dbAgent);

		// Getting permission
		let [ permissions ] = await dbAgent.query([
			'SELECT CONCAT(`groupName`, \".\", `signature`) as permPath',
			'FROM `MemberPermission`',
			'WHERE `member` = ?'
		].join(' '), [ memberId ]);

		return permissions.map((p) => {
			return p.permPath;
		})
	}

	getMiddleware(agent) {

		return (permPath) => {

			// Parsing permission path
			let perm = this.parsePermissionPath(permPath);
			const permInfo = this.perms[perm.groupName][perm.signature];
			if (!permInfo) {
				throw new Error('No such permission: ' + permPath);
			}

			const reject = async (ctx, next) => {

				// redirect or customized process
				if (permInfo.handlers.reject) {
					return await permInfo.handlers.reject(ctx, next);
				}

				return await this.defaultHandlers.reject(ctx, next);
			};

			const approve = async (ctx, next) => {

				// customized action for approve
				if (permInfo.handlers.approve) {
					return await permInfo.handlers.approve(ctx, next);
				}

				await next();
			};

			let check = async (ctx, next) => {

				// check whether client have tihs promission
				if (!ctx.state.session.perms.includes(permPath)) {
					return await reject(ctx, next);
				}

				await approve(ctx, next);
			};

			if (permInfo.handlers.check) {
				check = async (ctx, next) => {

					const callback = (async (ctx, next) => {

						// check whether client have tihs promission
						if (!ctx.state.session.perms.includes(permPath)) {
							return await reject(ctx, next);
						}

						await approve(ctx, next);
						
					}).bind(this, ctx, next);

					// Customized check
					await permInfo.handlers.check(ctx, callback);
				};
			}

			// Middleware for permission check
			return async (ctx, next) => {

				// User doens't have this permission
				if (ctx.state.session === undefined) {
					return await reject(ctx, next);
				}

				await check(ctx, next);
			};
		};
	}

	setDefaultHandler(state, handler) {
		this.defaultHandlers[state] = handler;
	}
};
