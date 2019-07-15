package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type creds struct {
	user      string
	clearPass string
	md5Pass   string
	sha1Pass  string
}

var wgFileReader = sync.WaitGroup{}

func main() {
	// Flags
	input := flag.String("input", "/Users/joshuahemmings/go/src/github.com/jLemmings/Unify/testDocuments", "Data to Import [STRING]")
	outFolder := flag.String("output", "/Users/joshuahemmings/go/src/github.com/jLemmings/Unify/out/", "output folder")
	stepSize := flag.Int("step", 50000, "step size")
	delimiters := flag.String("delimiters", ";:|", "delimiters list [STRING]")
	outputDelimiter := flag.String("outDelimiter", "|", "Output Delimiter [CHAR]")
	concurrency := flag.Int("concurrency", 10, "Concurrency (amount of GoRoutines) [INT]")

	if input == nil {
		log.Fatal("input Folder must be defined")
	} else if outFolder == nil {
		log.Fatal("Output Folder must be defined")
	}

	flag.Parse()



	compiledRegex := regexp.MustCompile("^(.*?)[" + *delimiters + "](.*)$")

	credChannel := make(chan creds, 1000)
	filePathChannel := make(chan string, *concurrency)
	stopToolChannel := make(chan bool, 1)
	stopFileWalkChannel := make(chan bool, 1)

	numberOfTxtFiles := 0
	numberOfProcessedFiles := 0

	// TODO: Remove for stable version
	go func() {
		// Create a new router
		router := mux.NewRouter()

		// Register pprof handlers
		router.HandleFunc("/debug/pprof/", pprof.Index)
		router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		router.HandleFunc("/debug/pprof/profile", pprof.Profile)
		router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)

		router.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
		router.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		router.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
		router.Handle("/debug/pprof/block", pprof.Handler("block"))
		router.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
		log.Fatal(http.ListenAndServe(":80", router))
	}()

	log.Println("Starting Import at", time.Now().Format("02-Jan-2006 15:04:05"))
	defer timeTrack(time.Now(), "Txt To Postgres")

	_ = filepath.Walk(*input,
		func(path string, file os.FileInfo, err error) error {
			if err != nil {
				log.Fatalf("Error reading %s: %v", path, err)
				return nil
			}
			if file.IsDir() {
				return nil
			}

			if filepath.Ext(file.Name()) == ".txt" {
				numberOfTxtFiles++
			}
			return nil
		})

	for i := 0; i < *concurrency; i++ {
		wgFileReader.Add(1)
		go readFile(filePathChannel, compiledRegex, credChannel, numberOfTxtFiles, &numberOfProcessedFiles, &wgFileReader)
	}

	go fileWriter(*outputDelimiter, *outFolder, *stepSize, credChannel, stopToolChannel)

	go fileWalk(input, filePathChannel, stopFileWalkChannel)

	<- stopFileWalkChannel
	close(filePathChannel)

	log.Println("Waiting for File Readers to finish")
	wgFileReader.Wait()
	log.Println("File Readers finished")
	close(credChannel)
	log.Println("Closed Credential Channel")


	<- stopToolChannel

}

func fileWriter(outputDelimiter string, outFolder string, stepSize int, credChannel chan creds, stopToolChannel chan bool) {
	log.Print("Starting file writer.")

	currentFile := 0
	currLine := 0
	currFile, err := os.Create(outFolder + "output-" + strconv.Itoa(currentFile) + ".txt")
	defer currFile.Close()
	currentFile++;
	if err != nil {
		log.Fatalf("Fatal Error: %v", err)
	}

	for {
		credential, more := <-credChannel

		if !more {
			log.Println(more)
			break
		}

		currFile.WriteString(credential.user + outputDelimiter + credential.clearPass + outputDelimiter +
			credential.md5Pass + outputDelimiter + credential.sha1Pass + "\n")
		currLine++
		if currLine%stepSize == 0 {
			err = currFile.Close()
			currFile, err = os.Create(outFolder + "output-" + strconv.Itoa(currentFile) + ".txt")
			currentFile++
		}


	}
	log.Print("Done writing.")

	stopToolChannel <- true

}

func readFile(filePathChannel chan string, delimiters *regexp.Regexp, credChannel chan creds, numberOfTxtFiles int, numberOfProcessedFiles *int, wg *sync.WaitGroup) {
	md5Regex := regexp.MustCompile("^[a-f0-9]{32}$")
	sha1Regex := regexp.MustCompile("\b[0-9a-f]{5,40}\b")

	for {
		path, morePaths := <-filePathChannel
		if morePaths {
			fileData, err := ioutil.ReadFile(path)
			if err != nil {
				log.Fatalf("Cannot read file %s", path)
				return
			}
			fileAsString := string(fileData)
			lines := strings.Split(fileAsString, "\n")

			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					strings.Replace(line, "\u0000", "", -1)
					insert := delimiters.ReplaceAllString(line, "${1}:$2")
					splitLine := strings.SplitN(insert, ":", 2)

					credentialForChan := creds{}

					if len(splitLine) == 2 && utf8.ValidString(splitLine[0]) && utf8.ValidString(splitLine[1]) {

						username := string(splitLine[0])
						password := string(splitLine[1])

						if md5Regex.Match([]byte(password)) {
							credentialForChan = creds{user: username, clearPass: "", md5Pass: password, sha1Pass: ""}
						} else if sha1Regex.Match([]byte(password)) {
							credentialForChan = creds{user: username, clearPass: "", md5Pass: password, sha1Pass: password}
						} else {
							credentialForChan = creds{user: username, clearPass: password, md5Pass: convToMd5(password), sha1Pass: convToSha1(password)}
						}
					}
					credChannel <- credentialForChan
				}
			}

			*numberOfProcessedFiles++
			log.Printf("Read %v / %v Files", *numberOfProcessedFiles, numberOfTxtFiles)
			runtime.GC()
		} else {
			log.Println("Closing readFile Goroutine")
			break
		}
	}
	wg.Done()
}

func fileWalk(dataSource *string, filePathChannel chan string, stopFileWalkChannel chan bool) {
	_ = filepath.Walk(*dataSource,
		func(path string, file os.FileInfo, err error) error {
			if err != nil {
				log.Fatalf("Error reading %s: %v", path, err)
				return nil
			}
			if file.IsDir() {
				return nil
			}

			if filepath.Ext(file.Name()) == ".txt" {
				// log.Printf("reading %s, %vB", path, file.Size())
				filePathChannel <- path
			}
			return nil
		})

	log.Println("stop file walk channel")
	stopFileWalkChannel <- true
}

func convToMd5(pass string) string {
	hasher := md5.New()
	hasher.Write([]byte(pass))
	return hex.EncodeToString(hasher.Sum(nil))
}

func convToSha1(pass string) string {
	hasher := sha1.New()
	hasher.Write([]byte(pass))
	return hex.EncodeToString(hasher.Sum(nil))
}

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Println("Finished Import at", time.Now().Format("02-Jan-2006 15:04:05"))
	log.Printf("%s took %s", name, elapsed)
}
