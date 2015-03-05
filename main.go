package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var keep, clean string
	var extensions string
	var dry bool

	flag.StringVar(&keep, "keep", "", "directory to look for dups, but delete nothing")
	flag.StringVar(&clean, "clean", "", "directory to find and delete dups")
	flag.BoolVar(&dry, "dry", false, "dry run--make no changes")
	flag.StringVar(&extensions, "extensions", "", "comma-seperated list of extensions to scan")
	flag.Parse()
	if keep == "" || clean == "" {
		fmt.Fprintf(os.Stderr, "-keep and -clean are both required\n")
		flag.Usage()
		os.Exit(1)
	}

	if dry {
		log.Printf("dry run: no files will be deleted")
	}
	suffixes := strings.Split(strings.ToLower(extensions), ",")

	// scan for sizes
	log.Printf("scanning %s for file sizes", keep)
	keeperSizes, err := scanSizes(keep, suffixes)
	if err != nil {
		os.Exit(1)
	}
	log.Printf("found %d keep file sizes", len(keeperSizes))
	log.Printf("scanning %s for file sizes", clean)
	cleanerSizes, err := scanSizes(clean, suffixes)
	if err != nil {
		os.Exit(1)
	}
	log.Printf("found %d clean file sizes", len(cleanerSizes))

	// find size matches
	filecount, bytecount := 0, 0
	for size, keeperNames := range keeperSizes {
		if cleanerNames, exists := cleanerSizes[size]; exists {
			// scan these files for content hashes
			keepers, err := scanHashes(keeperNames)
			if err != nil {
				os.Exit(1)
			}
			cleaners, err := scanHashes(cleanerNames)
			if err != nil {
				os.Exit(1)
			}

			// delete the dups
			for key, keeppath := range keepers {
				if cleanpath, exists := cleaners[key]; exists {
					filecount++
					bytecount += size

					if dry {
						log.Printf("found %s is dup of %s", cleanpath, keeppath)
					} else {
						log.Printf("deleting %s (dup of %s)", cleanpath, keeppath)
						if err := os.Remove(cleanpath); err != nil {
							log.Fatalf("error removing %s: %v", cleanpath, err)
						}
					}
				}
			}
		}
	}

	log.Printf("found %d duplicate files with total size %d (%.2f MB / %.2f GB)", filecount, bytecount, float64(bytecount)/(1024*1024), float64(bytecount)/(1024*1024*1024))
}

func scanSizes(root string, suffixes []string) (map[int][]string, error) {
	names := make(map[int][]string)
	err := filepath.Walk(root, func(path string, info os.FileInfo, inerr error) error {
		if inerr != nil {
			log.Printf("error walking directories, skipping: %v", inerr)
			return filepath.SkipDir
		}
		if info.IsDir() {
			//log.Printf(" --> %s", path)
		}
		if info.Mode()&os.ModeType != 0 {
			// skip everything but regular files
			return nil
		}

		// only consider files with requested extensions
		if len(suffixes) > 0 {
			keep := false
			for _, ext := range suffixes {
				if strings.HasSuffix(strings.ToLower(path), "."+ext) {
					keep = true
					break
				}
			}
			if !keep {
				return nil
			}
		}

		size := int(info.Size())
		names[size] = append(names[size], path)
		return nil
	})
	if err != nil {
		log.Printf("error walking %s: %v", root, err)
		return nil, err
	}
	return names, nil
}

func scanHashes(paths []string) (map[string]string, error) {
	files := make(map[string]string)
	for _, path := range paths {
		// compute a hash
		fp, err := os.Open(path)
		if err != nil {
			log.Printf("error opening file %s to take hash; skipping: %v", path, err)
			continue
		}
		hash := sha256.New()
		if _, err = io.Copy(hash, fp); err != nil {
			log.Printf("error computing hash for %s; skipping: %v", path, err)
			fp.Close()
			continue
		}
		fp.Close()
		sum := hex.EncodeToString(hash.Sum(nil))
		files[sum] = path
	}
	return files, nil
}
