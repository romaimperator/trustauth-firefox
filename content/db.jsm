/**
 * This is the database code for the TrustAuth addon. This is browser specific code.
 *
 * @author Daniel Fox
 * @link trustauth.com
 * @license BSD-3 Clause License http://opensource.org/licenses/BSD-3-Clause
 *
 * Copyright (c) 2012, Daniel Fox
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 *     Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *     Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *     Neither the name of TrustAuth nor the names of its contributors may be used to endorse or promote products derived from this software
 *         without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
var EXPORTED_SYMBOLS = [ 'db' ];

Components.utils.import("chrome://trustauth/content/utils.jsm");
Components.utils.import("chrome://trustauth/content/constants.jsm");
Components.utils.import("chrome://trustauth/content/crypto.jsm");
Components.utils.import("chrome://trustauth/content/migrations.jsm");

var db = {
  version: null,//this._get_version() || this.set_version(BASE_VERSION),
  manager: Manager(this),

  /**
   * This function wraps some SQL execution in the try...catch...finally and returns a boolean
   * result on success or failure.
   *
   * @param {string} sql string of SQL code to pass to createStatement
   * @param {function(statement)} statement_handler a function that takes the statement as a parameter and does stuff with the statement
   * @return {bool} true on success, false if there was an error
   */
  _execute: function(sql, statement_handler) {
    var db = this.connect();

    var result = false;
    try {
      var statement = db.createStatement(sql);
      if (statement_handler) { statement_handler(statement); }
      else { statement.execute(); }
      result = true;
    } catch (e) {
      utils.dump(e);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }
    return result;
  },

  _get_version: function() {
    var version = null;
    this._execute("SELECT version FROM migrations", function(statement) {
      if (statement.executeStep()) {
        version = statement.row.version;
      }
    });
    return version;
  },

  // Functions for the migrations
  get_version: function() {
    //return this.version;
    return this._get_version();
  },

  set_version: function(version) {
    return this._execute("UPDATE migrations SET version=:version", function(statement) {
      statement.params.version = version;
      statement.execute();
      this.version = version;
    });
  },

  reset: function() {
    return this._execute("DROP TABLE migrations");
  },

  _serialize: function(hash) {
    var r = [];
    for (key in hash) {
      r.push(key + " " + hash[key]);
    }
    return r.join(',');
  },

  create_table: function(name, columns) {
    return {
      up: function(db) { db._create_table(name, columns); },
      down: function(db) { db._drop_table(name); },
    };
  },

  _create_table: function(name, columns) {
    this._execute("CREATE TABLE :name (:columns)", function(statement) {
      statement.params.name = name;
      statement.params.columns = this._serialize(columns);
      statement.execute();
    });
  },

  _drop_table: function(name) {
    this._execute("DROP TABLE :name", function(statement) {
      statement.params.name = name;
      statement.execute();
    });
  },

  _add_column: function(table, column_name, column_def) {
    this._execute("ALTER TABLE :table ADD COLUMN :column", function(statement) {
      statement.params.table = table;
      statement.params.column = column_name + " " + column_def;
      statement.execute();
    });
  },

  _drop_columns: function(table, column_names) {
    var schema = [];
    this._execute("PRAGMA table_info(:table)", function(statement) {
      statement.params.table = table;
      while (statement.executeStep()) {
        schema.push({
          cid: statement.row.cid,
          name: statement.row.name,
          type: statement.row.type,
          notnull: statement.row.notnull,
          dflt_value: statement.row.dflt_value,
          pk: statement.row.pk,
        });
      }
    });
    schema = schema.filter(function(column) {
      for (index in column_names) {
        if (column_names[index] === column.name) { return false; }
      }
      return true;
    });
    this._create_table(table + "_new", schema.reduce(function(a, b) { a[b.name] = this._prepare_column_def(b); }, {}));
    this._execute("INSERT INTO :new SELECT :columns FROM :old", function(statement) {
      statement.params.new = table + "_new";
      statement.params.old = table;
      statement.params.columns = schema.map(function(column) { return column.name; }).join(",");
      statement.execute();
    });
    this._drop_table(table);
    this._execute("ALTER TABLE :new RENAME TO :old", function(statement) {
      statement.params.new = table + "_new";
      statement.params.old = table;
      statement.execute();
    });
  },

  _prepare_column_def: function(c) {
    var result = c.type + " DEFAULT (" + c.dflt_value + ") ";
    if (c.pk) { result += " PRIMARY KEY "; }
    if (c.notnull) { result += " NOT NULL "; }
    return result;
  },

  drop_table: function(name, columns) {
    return {
      up: function(db) { db._drop_table(name); }
      down: function(db) { db._create_table(name, columns); }
    };
  },

  add_column: function(table, columns) {
    return {
      up: function(db) {
        for (key in columns) {
          db._add_column(table, key, columns[key]);
        }
      },
      down: function(db) {
        for (key in columns) {
          db._drop_column(table, key);
        }
      },
    };
  },


  /*
   * Connects to the database.
   */
  connect: function() {
    Components.utils.import("resource://gre/modules/Services.jsm");
    Components.utils.import("resource://gre/modules/FileUtils.jsm");

    // Establish a connection to the database
    var file = FileUtils.getFile("ProfD", ["trustauth", "trustauth.sqlite"]);
    var file_exists = file.exists();
    return Services.storage.openDatabase(file);
  },

  /**
   * Associates the given key id with the given domain id. This function fails if the key is
   * already assigned to another domain.
   *
   * @param {integer} key_id the key id to associate this domain to
   * @param {integer} site_id the id of the domain to associate this key to
   * @return {bool} true if successful; false otherwise
   */
  associate_key: function(key_id, site_id) {
    var db = this.connect();

    var result = false;
    // If this key is available then assign it to this domain
    if ( ! this.is_key_assigned(key_id)) {
      try {
        var statement = db.createStatement("INSERT INTO keys_sites (key_id, site_id) VALUES(:key_id, :site_id)");
        statement.params.key_id  = key_id;
        statement.params.site_id = site_id;
        statement.execute();
        utils.log('key associated successfully');
        result = true;
      } catch (e) {
        utils.dump(e);
        utils.log(db.lastErrorString);
      } finally {
        statement.finalize();
        db.close();
      }
    }
    return result;
  },

  /*
   * Checks to see if the given domain has a key in the database
   *
   * @param domain the domain to look for
   * @return true if the domain is in the database false otherwise
   */
  domain_exist: function(domain) {
    var db = this.connect();

    var domain_exists = false;
    try {
      // Create the statement to fetch the most recently created key for this domain
      var statement = db.createStatement("SELECT domain FROM keys, sites, keys_sites WHERE keys.id=keys_sites.key_id AND sites.id=keys_sites.site_id AND sites.domain=:domain ORDER BY keys.created DESC");

      // Bind the parameter
      statement.params.domain = domain;

      // Execute the query synchronously
      if (statement.executeStep()) {
        domain_exists = domain === statement.row.domain;
      }
    } catch (ex) {
      utils.dump(ex);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return domain_exists;
  },

  /**
   * Fetches the first cached key id from the database.
   */
  fetch_cache_id: function() {
    var db = this.connect();

    var key_id = null;
    try {
      var statement = db.createStatement("SELECT id FROM keys WHERE id not in (SELECT key_id FROM keys_sites) LIMIT 1");
      if (statement.executeStep()) {
        key_id = statement.row.id;
      }
    } catch (e) {
      utils.dump(e);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return key_id;
  },

  /*
   * Fetches the most recently created key pair for the given domain, decrypts them
   * using the encryption key and returns the pair as a hash.
   *
   * @param domain the domain to fetch keys for
   * @return hash of the public and private key pair or null if the domain doesn't have a key pair
   */
  fetch_key_pair: function(domain) {
    var db = this.connect();

    var key_pair = null;
    try {
      var statement = db.createStatement("SELECT k.id, public_key, private_key FROM keys as k, sites as s, keys_sites as ks WHERE k.id=ks.key_id AND s.id=ks.site_id AND s.domain=:domain ORDER BY k.created DESC");

      // Bind the parameter
      statement.params.domain = domain;

      // Execute the query synchronously
      if (statement.executeStep()) {
        key_pair = {
          'id': statement.row.id,
          'public_key': statement.row.public_key,
          'private_key': statement.row.private_key,
        };
      } else {
        utils.log("could not find key_pair for domain: " + domain);
      }
    } catch (ex) {
      utils.dump(ex);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return key_pair;
  },

  /**
   * Adds the domain name to the database and returns the site_id of the domain.
   *
   * @param {string} domain the domain name to add
   * @return {integer} the id of the either the new domain or the previously inserted domain
   */
  fetch_or_store_domain: function(domain) {
    var db = this.connect();

    // First try to insert the domain if it's not already there.
    var site_id = this.get_site_id(domain);
    if (site_id === null) {
      try {
        var statement = db.createStatement("INSERT INTO sites (domain) VALUES(:domain)");
        statement.params.domain = domain;
        statement.execute();

        site_id = db.lastInsertRowID;
      } catch (e) {
        utils.log(db.lastErrorString);
        utils.dump(e);
      } finally {
        statement.finalize();
        db.close();
      }
    }

    return site_id;
  },

  /**
   * Retrieves the hash stored in the database.
   *
   * @return {string} the hash if there is one, null otherwise
   */
  get_stored_hash: function() {
    var db = this.connect();

    var hash = null;
    try {
      var statement = db.createStatement("SELECT hash FROM password_verify LIMIT 1");

      if (statement.executeStep()) {
        hash = statement.row.hash;
      }
    } catch(ex) {
      utils.dump(ex);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return hash;
  },

  /*
   * Returns the site_id for the domain or null if the domain wasn't found.
   *
   * @param domain the domain to get the site_id for
   * @return the site_id
   */
  get_site_id: function(domain) {
    var db = this.connect();

    var row_id = null;
    try {
      var statement = db.createStatement("SELECT id FROM sites WHERE domain=:domain");
      statement.params.domain = domain;
      if (statement.executeStep()) {
        row_id = statement.row.id;
      }
    } catch (ex) {
      utils.dump(ex);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
    }

    db.close();
    return row_id;
  },

  /*
   * Initializes the place to store the public and private key pairs.
   */
  init: function() {
    this.manager.add_migration("Create keys table", {
      up: function(db) {
        return db._execute(function(con) {
          con.executeSimpleSQL("CREATE TABLE keys (id INTEGER PRIMARY KEY, public_key TEXT, private_key TEXT, created TEXT)");
        });
      },
      down: function(db) {
        return db._execute(function(con) {
          con.executeSimpleSQL("DROP TABLE keys");
        });
    }});
    var db = this.connect();

    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, public_key TEXT, private_key TEXT, created TEXT)");
    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY, domain TEXT UNIQUE)");
    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS keys_sites (key_id NUMERIC, site_id NUMERIC)");
    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS password_verify (hash TEXT)");
    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS migrations (version INTEGER)");
    db.executeSimpleSQL("INSERT INTO migrations (version) VALUES (" + BASE_VERSION + ")");

    db.close();
  },

  /**
   * Checks to see if the key_id is already assigned to a domain.
   *
   * @param {integer} key_id the key id to check
   * @return {bool} true if the key is assigned already; false otherwise
   */
  is_key_assigned: function(key_id) {
    var db = this.connect();

    var result = false;
    try {
      var statement = db.createStatement("SELECT * FROM keys_sites WHERE key_id=:key_id");
      statement.params.key_id = key_id;

      if (statement.executeStep()) {
        if (statement.row.key_id) {
          result = true;
        }
      }
    } catch (e) {
      utils.dump(e);
      utils.log(db.lastErrorString);
      result = true;
    } finally {
      statement.finalize();
      db.close();
    }

    return result;
  },

  /**
   * Stores a cache key in the database for future use.
   *
   * @param {forge key objects} keys the key pair to store as the next cache key.
   */
  store_cache_pair: function(public_key, private_key) {
    var db = this.connect();

    var result = false;
    try {
      var statement = db.createStatement("INSERT INTO keys (public_key, private_key, created) VALUES(:public_key, :private_key, :created)");
      statement.params.public_key  = public_key;
      statement.params.private_key = private_key;
      statement.params.created     = utils.get_time();
      if (statement.executeStep()) result = true;
    } catch (e) {
      utils.dump(e);
      utils.log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return result;
  },

  /*
   * This function stores the key in the browser's password manager
   *
   * @param key the key to store
   */
  store_encryption_key: function(key) {
    var success = false;
    if (! is_password_set()) {
      var db = this.connect();

      try {
        var statement = db.createStatement("INSERT OR ABORT INTO password_verify (hash) VALUES(:hash)");
        statement.params.hash = this.get_storage_hash(key);

        success = statement.executeStep();
      } catch (ex) {
        utils.dump(ex);
        utils.log(db.lastErrorString);
      } finally {
        statement.finalize();
        db.close();
      }

    }
    return success;
  },

};
