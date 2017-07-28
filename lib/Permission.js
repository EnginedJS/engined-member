
const registerPermission = (service, groupName, signature, descriptor, approve, reject) => {

	if (service.perms[groupName] === undefined)
		service.perms[groupName] = {};

	if (service.perms[groupName][signature] !== undefined) {
		throw new Error('Permission \"' + groupName + '.' + signature + '\" exists already');
	}

	service.perms[groupName][signature] = {
		descriptor: descriptor,
		approve: approve,
		reject: reject 
	};
};

const unregisterPermission = (service, groupName, signature) => {
	if (service.perms[groupName] === undefined)
		return;

	if (service.perms[groupName][signature] === undefined)
		return;

	delete service.perms[groupName][signature];
};

const unregisterPermissionGroup = (service, groupName) => {
	if (service.perms[groupName] === undefined)
		return;

	delete service.perms[groupName];
};

const parsePermissionPath = (service, permPath) => {

	let parts = permPath.split('.');
	let groupName = parts.shift();
	let signature = parts.join('.');

	return {
		groupName: groupName,
		signature: signature
	}
};

const addPermission = async (service, memberId, permissions) => {

	// Getting database agent
	let dbAgent = service.getContext().get('MySQL')[service.agent.dbAgent];

	try {
		// Preparing permission records
		let values = permissions.map((permPath) => {

			let perm = parsePermissionPath(service, permPath);

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
};

const getPermissions = async (service, memberId) => {

	// Getting member system agent
	let agent = service.getContext().get('Member')[service.memberAgent];

	// Getting database agent
	let dbAgent = service.getContext().get('MySQL')[agent.dbAgent];

	// Getting permission
	let [ permissions ] = await dbAgent.query([
		'SELECT CONCAT(`groupName`, \".\", `signature`) as permPath',
		'FROM `MemberPermission`',
		'WHERE `id` = ?'
	].join(' '), [ memberId ]);

	return permissions.map((p) => {
		return p.permPath;
	})
};

const getMiddleware = (service) => {

	return (permPath) => {

		// Parsing permission path
		let perm = parsePermissionPath(service, permPath);
		let permInfo = service.perms[perm.groupName][perm.signature];
		if (!permInfo) {
			throw new Error('No such permission: ' + permPath);
		}

		// Middleware
		return async (ctx, next) => {

			// User doens't have this permission
			if (ctx.state.session === undefined ||
			    ctx.state.session.perms.indexOf(permPath) === -1) {

				// redirect or customized process
				if (permInfo.reject) {
					return await permInfo.reject(ctx, next);
				}

				return await service.defaultReject(ctx, next);
			}

			// do something to check permission
			if (permInfo.approve) {
				return await permInfo.approve(ctx, next);
			}

			await next();
		};
	};
};

module.exports = (service) => {

	return {
		registerPermission: registerPermission.bind(this, service),
		unregisterPermission: unregisterPermission.bind(this, service),
		unregisterPermissionGroup: unregisterPermissionGroup.bind(this, service),
		parsePermissionPath: parsePermissionPath.bind(this, service),
		addPermission: addPermission.bind(this, service),
		getPermissions: getPermissions.bind(this, service),
		getMiddleware: getMiddleware.bind(this, service)
	};
};
