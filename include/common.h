/*
 *  common.h - common definitions
 *  (c) John Weber, rjohnweber@gmail.com
 * 
 *  This file is part of the GLIVE package.
 *
 *  Videodemo is free software: you can redistribute it and/or modify
 *  it under the terms of version 2 of GNU General Public License as 
 *  published by the Free Software Foundation.
 *
 *  Videodemo is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with the videodemo package.  If not, see 
 *  <http://www.gnu.org/licenses/>.
 */


#ifndef COMMON_H_
#define COMMON_H_

#ifdef DEBUG
#define debug_printf(...) \
            do { if (DEBUG) fprintf(stderr, ##__VA_ARGS__); } while (0)
#else
#define debug_printf(...) \
						do { if (0) fprintf(stderr, ##__VA_ARGS__); } while (0)
#endif

#endif /* COMMON_H_ */
